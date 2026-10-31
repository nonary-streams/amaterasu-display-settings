//! Nonblocking durable callback receipts and physical recovery obligations.
//!
//! The module must authenticate the selected coordinator, its current epoch,
//! target ownership and admission before constructing this adapter. The state
//! service scopes storage by the broker caller; it does not authenticate the
//! application-level target. `advance` drives I/O and never performs a native
//! effect. Unknown state writes require reconciliation before retry.
use amaterasu_module_sdk::{Command, ModuleResult, Response};
use serde_json::{Value, json};

use crate::physical_callback::{CallbackResult, DurableStore, StoreCommand, StoreProgress};
use crate::physical_display::RecoveryObligation;
use crate::receipt_store::{
    self, Operation, Outcome, PendingStoreOperation, Progress, VerifiedEpoch,
};

const SERVICE: &str = "amaterasu.state/1";
const MAX_FAILURES: u8 = 3;

/// A target token must come from an authenticated coordinator admission, not
/// from unverified payload fields. The predicate must check exact target scope.
pub struct VerifiedTarget(String);
impl VerifiedTarget {
    pub fn authenticate(
        target: String,
        verify: impl FnOnce(&str) -> bool,
    ) -> Result<Self, &'static str> {
        if target.is_empty()
            || target.len() > 160
            || target.chars().any(char::is_control)
            || !verify(&target)
        {
            return Err("target_not_authenticated");
        }
        Ok(Self(target))
    }
}

struct ActiveReceipt {
    sequence: u64,
    operation_id: String,
    request: Value,
}
struct Exchange {
    command: Command,
    request_id: Option<u64>,
    result: Option<Value>,
    failures: u8,
    uncertain: bool,
}
struct JournalOperation {
    requested: StoreCommand,
    key: String,
    stage: JournalStage,
    exchange: Exchange,
    attempts: u8,
    expected_revision: Option<u64>,
    verified: Option<RecoveryObligation>,
    saved: Option<RecoveryObligation>,
    deadline_ms: u64,
    broker_prefix: String,
    operation_id: String,
}
#[derive(Clone, Copy)]
enum JournalStage {
    Read,
    Write,
}
enum Active {
    Receipt {
        command: StoreCommand,
        call: PendingStoreOperation,
    },
    Journal(JournalOperation),
}

/// One adapter per in-flight callback. Keep calling `advance` once per event
/// loop tick, then pass the adapter to `PhysicalCallback::poll`. The broker
/// prefix must be globally unique per adapter; no identity comes from payload.
pub struct StateDurableStore {
    epoch: VerifiedEpoch,
    target: VerifiedTarget,
    prefix: String,
    parent: Option<u64>,
    timeout_ms: u64,
    now_ms: u64,
    counter: u64,
    active: Option<Active>,
    ready: Option<(StoreCommand, StoreProgress)>,
    receipt: Option<ActiveReceipt>,
    verified_prior: Option<RecoveryObligation>,
    saved: Option<RecoveryObligation>,
    poisoned: bool,
    load: Option<LoadOperation>,
    load_ready: Option<Option<Value>>,
}
impl StateDurableStore {
    /// Start reading the obligation for this already-authenticated target.
    pub fn start_load(&mut self) -> Result<(), &'static str> {
        if self.poisoned
            || self.active.is_some()
            || self.ready.is_some()
            || self.load.is_some()
            || self.load_ready.is_some()
        {
            return Err("store_busy_or_unavailable");
        }
        let prefix = self.next_prefix().ok_or("operation_exhausted")?;
        self.load = Some(LoadOperation::new(
            self.key(),
            prefix,
            self.parent,
            self.timeout_ms,
            self.now_ms,
        ));
        Ok(())
    }

    pub fn poll_load(&mut self) -> LoadProgress<RecoveryObligation> {
        if self.poisoned {
            return LoadProgress::Unknown;
        }
        match self.load_ready.take() {
            Some(Some(value)) => match serde_json::from_value::<RecoveryObligation>(value) {
                Ok(obligation) if valid_physical(&obligation) => LoadProgress::Found(obligation),
                _ => {
                    self.poisoned = true;
                    LoadProgress::Unknown
                }
            },
            Some(None) => LoadProgress::Absent,
            None if self.load.is_some() => LoadProgress::Waiting,
            None => LoadProgress::Unknown,
        }
    }
    pub fn new(
        epoch: VerifiedEpoch,
        target: VerifiedTarget,
        prefix: String,
        parent: Option<u64>,
        timeout_ms: u64,
    ) -> Result<Self, &'static str> {
        if prefix.is_empty()
            || prefix.len() > 80
            || !prefix.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'_' | b'-' | b'/')
            })
            || !(1..=30_000).contains(&timeout_ms)
        {
            return Err("invalid_broker_operation");
        }
        Ok(Self {
            epoch,
            target,
            prefix,
            parent,
            timeout_ms,
            now_ms: 0,
            counter: 0,
            active: None,
            ready: None,
            receipt: None,
            verified_prior: None,
            saved: None,
            poisoned: false,
            load: None,
            load_ready: None,
        })
    }
    fn key(&self) -> String {
        format!("physical-obligation/v1/{}", self.target.0)
    }
    fn next_prefix(&mut self) -> Option<String> {
        self.counter = self.counter.checked_add(1)?;
        Some(format!("{}.{}", self.prefix, self.counter))
    }
    /// Run at most one state-service broker command. The supplied clock must be
    /// monotonic and share the caller's deadline units.
    pub fn advance(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) {
        if now_ms < self.now_ms {
            self.poisoned = true;
            return;
        }
        self.now_ms = now_ms;
        if let Some(mut load) = self.load.take() {
            match load.advance(now_ms, send) {
                LoadStep::Waiting => self.load = Some(load),
                LoadStep::Done(result) => match result {
                    Ok(value) => self.load_ready = Some(value),
                    Err(()) => self.poisoned = true,
                },
            }
            return;
        }
        let Some(active) = self.active.take() else {
            return;
        };
        match active {
            Active::Receipt { command, mut call } => match call.poll(now_ms, send) {
                Progress::Waiting => self.active = Some(Active::Receipt { command, call }),
                Progress::Done(outcome) => {
                    let result = match (&command, outcome) {
                        (
                            StoreCommand::Reserve {
                                sequence,
                                operation_id,
                                request,
                            },
                            Outcome::Begun,
                        ) => {
                            self.receipt = Some(ActiveReceipt {
                                sequence: *sequence,
                                operation_id: operation_id.clone(),
                                request: request.clone(),
                            });
                            StoreProgress::Reserved
                        }
                        (StoreCommand::Reserve { .. }, Outcome::RecoveryRequired(_)) => {
                            StoreProgress::ExistingPending
                        }
                        (StoreCommand::Reserve { .. }, Outcome::Completed(receipt)) => {
                            match receipt.state {
                                receipt_store::ReceiptState::Completed { result } => {
                                    serde_json::from_value(result).map_or(
                                        StoreProgress::Unknown,
                                        StoreProgress::ExistingComplete,
                                    )
                                }
                                _ => StoreProgress::Unknown,
                            }
                        }
                        (StoreCommand::Complete { .. }, Outcome::Completed(_)) => {
                            StoreProgress::Completed
                        }
                        _ => StoreProgress::Unknown,
                    };
                    self.ready = Some((command, result));
                }
            },
            Active::Journal(mut journal) => {
                match journal.advance(now_ms, self.timeout_ms, self.parent, &self.prefix, send) {
                    JournalProgress::Waiting => self.active = Some(Active::Journal(journal)),
                    JournalProgress::Done(result) => {
                        if result == StoreProgress::Verified
                            && let StoreCommand::VerifyPrior { obligation } = &journal.requested
                        {
                            self.verified_prior = Some(obligation.clone());
                        }
                        if result == StoreProgress::Saved
                            && let StoreCommand::Save { obligation, .. } = &journal.requested
                        {
                            self.saved = Some(obligation.clone());
                        }
                        self.ready = Some((journal.requested, result));
                    }
                }
            }
        }
    }
    fn start(&mut self, command: &StoreCommand) -> Result<Active, ()> {
        let prefix = self.next_prefix().ok_or(())?;
        match command {
            StoreCommand::Reserve {
                sequence,
                operation_id,
                request,
            } => {
                if self.receipt.is_some() {
                    return Err(());
                }
                let operation = Operation::Begin {
                    epoch: self.epoch.clone(),
                    sequence: *sequence,
                    operation_id: operation_id.clone(),
                    request: request.clone(),
                };
                let call = PendingStoreOperation::new(
                    operation,
                    prefix,
                    self.parent,
                    self.timeout_ms,
                    self.now_ms,
                )
                .map_err(|_| ())?;
                Ok(Active::Receipt {
                    command: command.clone(),
                    call,
                })
            }
            StoreCommand::Complete {
                sequence,
                operation_id,
                result,
            } => {
                let receipt = self.receipt.as_ref().ok_or(())?;
                if receipt.sequence != *sequence || receipt.operation_id != *operation_id {
                    return Err(());
                }
                let saved = self.saved.as_ref().ok_or(())?;
                let durable_result = match result {
                    CallbackResult::Applied { lease } => {
                        saved.lease.as_ref() == Some(lease) && !saved.restored
                    }
                    CallbackResult::Restored { lease } => {
                        saved.lease.as_ref() == Some(lease) && saved.restored
                    }
                    CallbackResult::Rejected { .. } => saved.lease.is_none() && !saved.restored,
                    CallbackResult::RecoveryRequired => false,
                };
                if !durable_result {
                    return Err(());
                }
                let result = serde_json::to_value(result).map_err(|_| ())?;
                let operation = Operation::Complete {
                    epoch: self.epoch.clone(),
                    sequence: *sequence,
                    operation_id: operation_id.clone(),
                    request: receipt.request.clone(),
                    result,
                };
                let call = PendingStoreOperation::new(
                    operation,
                    prefix,
                    self.parent,
                    self.timeout_ms,
                    self.now_ms,
                )
                .map_err(|_| ())?;
                Ok(Active::Receipt {
                    command: command.clone(),
                    call,
                })
            }
            StoreCommand::VerifyPrior { obligation } => {
                if self.receipt.is_none() || obligation.lease.is_none() || obligation.restored {
                    return Err(());
                }
                Ok(Active::Journal(JournalOperation::new(
                    command.clone(),
                    self.key(),
                    prefix,
                    self.parent,
                    self.timeout_ms,
                    self.now_ms,
                    self.verified_prior.clone(),
                    self.saved.clone(),
                    self.receipt.as_ref().ok_or(())?.operation_id.clone(),
                )))
            }
            StoreCommand::Save { sequence, .. } => {
                if self
                    .receipt
                    .as_ref()
                    .is_none_or(|r| r.sequence != *sequence)
                {
                    return Err(());
                }
                Ok(Active::Journal(JournalOperation::new(
                    command.clone(),
                    self.key(),
                    prefix,
                    self.parent,
                    self.timeout_ms,
                    self.now_ms,
                    self.verified_prior.clone(),
                    self.saved.clone(),
                    self.receipt.as_ref().ok_or(())?.operation_id.clone(),
                )))
            }
        }
    }
}
impl DurableStore for StateDurableStore {
    fn poll(&mut self, command: &StoreCommand) -> StoreProgress {
        if self.poisoned {
            return StoreProgress::Unknown;
        }
        if self.load.is_some() || self.load_ready.is_some() {
            return StoreProgress::Unknown;
        }
        if let Some((ready_command, result)) = self.ready.take() {
            if &ready_command != command {
                self.poisoned = true;
                return StoreProgress::Unknown;
            }
            if result == StoreProgress::Unknown {
                self.poisoned = true;
            }
            return result;
        }
        if let Some(active) = &self.active {
            let active_command = match active {
                Active::Receipt { command, .. } => command,
                Active::Journal(journal) => &journal.requested,
            };
            if active_command != command {
                self.poisoned = true;
                return StoreProgress::Unknown;
            }
            return StoreProgress::Waiting;
        }
        match self.start(command) {
            Ok(active) => {
                self.active = Some(active);
                StoreProgress::Waiting
            }
            Err(()) => {
                self.poisoned = true;
                StoreProgress::Unknown
            }
        }
    }
}

// A separate state key stores the physical obligation independently of the
// operation receipt. This allows a completed prepare to retain a live lease.
impl JournalOperation {
    #[allow(clippy::too_many_arguments)]
    fn new(
        requested: StoreCommand,
        key: String,
        prefix: String,
        parent: Option<u64>,
        timeout_ms: u64,
        now_ms: u64,
        verified: Option<RecoveryObligation>,
        saved: Option<RecoveryObligation>,
        operation_id: String,
    ) -> Self {
        let payload = json!({"action":"get","key":key});
        Self {
            requested,
            key,
            stage: JournalStage::Read,
            exchange: Exchange {
                command: Command::Request {
                    service: SERVICE.into(),
                    payload,
                    timeout_ms,
                    operation_id: format!("{prefix}.read.0"),
                    parent,
                },
                request_id: None,
                result: None,
                failures: 0,
                uncertain: false,
            },
            attempts: 0,
            expected_revision: None,
            verified,
            saved,
            deadline_ms: now_ms.saturating_add(timeout_ms),
            broker_prefix: prefix,
            operation_id,
        }
    }
    fn restart_read(&mut self, timeout_ms: u64, parent: Option<u64>) {
        self.stage = JournalStage::Read;
        self.exchange = Exchange {
            command: Command::Request {
                service: SERVICE.into(),
                payload: json!({"action":"get","key":self.key}),
                timeout_ms,
                operation_id: format!("{}.read.{}", self.broker_prefix, self.attempts),
                parent,
            },
            request_id: None,
            result: None,
            failures: 0,
            uncertain: false,
        };
    }
    fn advance(
        &mut self,
        now_ms: u64,
        timeout_ms: u64,
        parent: Option<u64>,
        _prefix: &str,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> JournalProgress {
        if now_ms >= self.deadline_ms || self.exchange.failures >= MAX_FAILURES {
            return JournalProgress::Done(StoreProgress::Unknown);
        }
        if let Some(id) = self.exchange.request_id {
            if self.exchange.result.is_some() {
                match send(Command::ReleaseResult { request: id }) {
                    Ok(Response::Ok) => {
                        let result = self.exchange.result.take().expect("result");
                        self.consume(result, timeout_ms, parent)
                    }
                    _ => {
                        self.exchange.failures += 1;
                        JournalProgress::Waiting
                    }
                }
            } else {
                match send(Command::TakeResult { request: id }) {
                    Ok(Response::Pending) => JournalProgress::Waiting,
                    Ok(Response::Result { payload }) => {
                        self.exchange.result = Some(payload);
                        JournalProgress::Waiting
                    }
                    _ => {
                        self.exchange.failures += 1;
                        JournalProgress::Waiting
                    }
                }
            }
        } else {
            match send(self.exchange.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.exchange.request_id = Some(id);
                    self.exchange.failures = 0;
                    JournalProgress::Waiting
                }
                Ok(Response::Error { .. }) if !self.exchange.uncertain => {
                    JournalProgress::Done(StoreProgress::Unknown)
                }
                _ => {
                    self.exchange.uncertain = true;
                    self.exchange.failures += 1;
                    JournalProgress::Waiting
                }
            }
        }
    }
    fn consume(&mut self, payload: Value, timeout_ms: u64, parent: Option<u64>) -> JournalProgress {
        let Some(ok) = payload.get("ok").and_then(Value::as_bool) else {
            return JournalProgress::Done(StoreProgress::Unknown);
        };
        if !ok {
            if matches!(self.stage, JournalStage::Write)
                && payload.pointer("/error/code").and_then(Value::as_str)
                    == Some("revision_conflict")
            {
                self.attempts += 1;
                if self.attempts < MAX_FAILURES {
                    self.restart_read(timeout_ms, parent);
                    return JournalProgress::Waiting;
                }
            }
            return JournalProgress::Done(StoreProgress::Unknown);
        }
        match self.stage {
            JournalStage::Write => {
                if payload.get("revision").and_then(Value::as_u64) == self.expected_revision {
                    JournalProgress::Done(StoreProgress::Saved)
                } else {
                    JournalProgress::Done(StoreProgress::Unknown)
                }
            }
            JournalStage::Read => {
                let Some(revision) = payload.get("revision").and_then(Value::as_u64) else {
                    return JournalProgress::Done(StoreProgress::Unknown);
                };
                let Some(found) = payload.get("found").and_then(Value::as_bool) else {
                    return JournalProgress::Done(StoreProgress::Unknown);
                };
                let Some(value) = payload.get("value") else {
                    return JournalProgress::Done(StoreProgress::Unknown);
                };
                let current = if found {
                    let Ok(obligation) =
                        serde_json::from_value::<RecoveryObligation>(value.clone())
                    else {
                        return JournalProgress::Done(StoreProgress::Unknown);
                    };
                    Some(obligation)
                } else if value.is_null() {
                    None
                } else {
                    return JournalProgress::Done(StoreProgress::Unknown);
                };
                match &self.requested {
                    StoreCommand::VerifyPrior { obligation } => {
                        if current.as_ref() == Some(obligation)
                            && !obligation.restored
                            && obligation.lease.is_some()
                        {
                            JournalProgress::Done(StoreProgress::Verified)
                        } else {
                            JournalProgress::Done(StoreProgress::Unknown)
                        }
                    }
                    StoreCommand::Save { obligation, .. } => {
                        if !self.allowed_save(current.as_ref(), obligation) {
                            return JournalProgress::Done(StoreProgress::Unknown);
                        }
                        let Some(next) = revision.checked_add(1) else {
                            return JournalProgress::Done(StoreProgress::Unknown);
                        };
                        self.expected_revision = Some(next);
                        self.stage = JournalStage::Write;
                        self.exchange = Exchange {
                            command: Command::Request {
                                service: SERVICE.into(),
                                payload: json!({"action":"set","key":self.key,"value":obligation,"expected_revision":revision}),
                                timeout_ms,
                                operation_id: format!(
                                    "{}.write.{}",
                                    self.broker_prefix, self.attempts
                                ),
                                parent,
                            },
                            request_id: None,
                            result: None,
                            failures: 0,
                            uncertain: false,
                        };
                        JournalProgress::Waiting
                    }
                    _ => JournalProgress::Done(StoreProgress::Unknown),
                }
            }
        }
    }
    fn allowed_save(
        &self,
        current: Option<&RecoveryObligation>,
        next: &RecoveryObligation,
    ) -> bool {
        let initial =
            next.operation_id == self.operation_id && next.lease.is_none() && !next.restored;
        let Some(current) = current else {
            return initial && self.saved.is_none() && self.verified.is_none();
        };
        if current.restored && initial && self.saved.is_none() && self.verified.is_none() {
            return true;
        }
        if self.saved.as_ref() != Some(current) && self.verified.as_ref() != Some(current) {
            return false;
        }
        if current == next {
            return true;
        }
        current.operation_id == next.operation_id
            && current.configuration == next.configuration
            && current.topology_revision == next.topology_revision
            && ((!current.restored
                && current.lease.is_none()
                && next.lease.is_some()
                && !next.restored)
                || (!current.restored
                    && current.lease.is_some()
                    && current.lease == next.lease
                    && next.restored))
    }
}
enum JournalProgress {
    Waiting,
    Done(StoreProgress),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::physical_display::{Configuration, DisplaySetting, Rational, Rotation};
    use std::collections::BTreeMap;

    fn epoch() -> VerifiedEpoch {
        VerifiedEpoch::authenticate("epoch-a".into(), |_| true).unwrap()
    }
    fn target() -> VerifiedTarget {
        VerifiedTarget::authenticate("session-1".into(), |_| true).unwrap()
    }
    fn obligation() -> RecoveryObligation {
        RecoveryObligation::new(
            "operation-1".into(),
            Configuration {
                displays: vec![DisplaySetting {
                    id: "display-1".into(),
                    width: 1920,
                    height: 1080,
                    refresh: Rational {
                        numerator: 60,
                        denominator: 1,
                    },
                    x: 0,
                    y: 0,
                    rotation: Rotation::Identity,
                    hdr_enabled: None,
                }],
            },
            "0123456789abcdef0123456789abcdef".into(),
        )
        .unwrap()
    }
    #[derive(Default)]
    pub(super) struct FakeState {
        revision: u64,
        values: BTreeMap<String, Value>,
        collection_revision: u64,
        metadata: Value,
        entries: BTreeMap<String, Value>,
        pending: Option<Value>,
        id: u64,
        fail_next_write: bool,
    }
    impl FakeState {
        pub(super) fn send(&mut self, command: Command) -> ModuleResult<Response> {
            match command {
                Command::Request { payload, .. } => {
                    let reply = match payload["action"].as_str().unwrap() {
                        "get" => {
                            let value = self.values.get(payload["key"].as_str().unwrap());
                            json!({"ok":true,"revision":self.revision,"found":value.is_some(),"value":value})
                        }
                        "set" => {
                            if self.fail_next_write {
                                self.fail_next_write = false;
                                return Err("unknown state write".into());
                            }
                            if payload["expected_revision"].as_u64() != Some(self.revision) {
                                json!({"ok":false,"error":{"code":"revision_conflict"}})
                            } else {
                                self.values.insert(
                                    payload["key"].as_str().unwrap().into(),
                                    payload["value"].clone(),
                                );
                                self.revision += 1;
                                json!({"ok":true,"revision":self.revision})
                            }
                        }
                        "collection_get" => {
                            json!({"ok":true,"revision":self.collection_revision,"found":self.collection_revision != 0,"metadata":self.metadata,"count":self.entries.len(),"value":self.entries.get(payload["key"].as_str().unwrap())})
                        }
                        "collection_commit" => {
                            if self.fail_next_write {
                                self.fail_next_write = false;
                                return Err("unknown state write".into());
                            }
                            if payload["expected_revision"].as_u64()
                                != Some(self.collection_revision)
                            {
                                json!({"ok":false,"error":{"code":"revision_conflict"}})
                            } else {
                                for edit in payload["edits"].as_array().unwrap() {
                                    let key = edit["key"].as_str().unwrap().to_owned();
                                    if edit["value"].is_null() {
                                        self.entries.remove(&key);
                                    } else {
                                        self.entries.insert(key, edit["value"].clone());
                                    }
                                }
                                self.metadata = payload["metadata"].clone();
                                self.collection_revision += 1;
                                json!({"ok":true,"revision":self.collection_revision})
                            }
                        }
                        _ => panic!("unexpected action"),
                    };
                    self.id += 1;
                    self.pending = Some(reply);
                    Ok(Response::Accepted { id: self.id })
                }
                Command::TakeResult { .. } => Ok(Response::Result {
                    payload: self.pending.clone().unwrap(),
                }),
                Command::ReleaseResult { .. } => {
                    self.pending = None;
                    Ok(Response::Ok)
                }
                _ => panic!("unexpected command"),
            }
        }
        fn drive(&mut self, store: &mut StateDurableStore, command: StoreCommand) -> StoreProgress {
            for _ in 0..50 {
                let progress = store.poll(&command);
                if progress != StoreProgress::Waiting {
                    return progress;
                }
                store.advance(store.now_ms + 1, &mut |cmd| self.send(cmd));
            }
            panic!("state operation stuck")
        }
    }
    fn store(prefix: &str) -> StateDurableStore {
        StateDurableStore::new(epoch(), target(), prefix.into(), None, 30_000).unwrap()
    }
    fn reserve(sequence: u64, id: &str) -> StoreCommand {
        StoreCommand::Reserve {
            sequence,
            operation_id: id.into(),
            request: json!({"operation":id}),
        }
    }
    fn complete(sequence: u64, id: &str, result: CallbackResult) -> StoreCommand {
        StoreCommand::Complete {
            sequence,
            operation_id: id.into(),
            result,
        }
    }
    #[test]
    fn prepare_and_release_keep_independent_durable_obligation() {
        let mut state = FakeState::default();
        let mut first = store("first");
        let mut o = obligation();
        assert_eq!(
            state.drive(&mut first, reserve(1, "operation-1")),
            StoreProgress::Reserved
        );
        assert_eq!(
            state.drive(
                &mut first,
                StoreCommand::Save {
                    sequence: 1,
                    obligation: o.clone()
                }
            ),
            StoreProgress::Saved
        );
        o.lease = Some("lease-1".into());
        assert_eq!(
            state.drive(
                &mut first,
                StoreCommand::Save {
                    sequence: 1,
                    obligation: o.clone()
                }
            ),
            StoreProgress::Saved
        );
        assert_eq!(
            state.drive(
                &mut first,
                complete(
                    1,
                    "operation-1",
                    CallbackResult::Applied {
                        lease: "lease-1".into()
                    }
                )
            ),
            StoreProgress::Completed
        );
        assert_eq!(
            state.values["physical-obligation/v1/session-1"]["lease"],
            "lease-1"
        );
        let mut release = store("release");
        assert_eq!(
            state.drive(&mut release, reserve(2, "operation-2")),
            StoreProgress::Reserved
        );
        assert_eq!(
            state.drive(
                &mut release,
                StoreCommand::VerifyPrior {
                    obligation: o.clone()
                }
            ),
            StoreProgress::Verified
        );
        assert_eq!(
            state.drive(
                &mut release,
                StoreCommand::Save {
                    sequence: 2,
                    obligation: o.clone()
                }
            ),
            StoreProgress::Saved
        );
        o.restored = true;
        assert_eq!(
            state.drive(
                &mut release,
                StoreCommand::Save {
                    sequence: 2,
                    obligation: o.clone()
                }
            ),
            StoreProgress::Saved
        );
        assert_eq!(
            state.drive(
                &mut release,
                complete(
                    2,
                    "operation-2",
                    CallbackResult::Restored {
                        lease: "lease-1".into()
                    }
                )
            ),
            StoreProgress::Completed
        );
        assert_eq!(
            state.values["physical-obligation/v1/session-1"]["restored"],
            true
        );
    }
    #[test]
    fn mismatch_and_unresolved_retry_never_authorize_effects() {
        let mut state = FakeState::default();
        let mut first = store("first");
        assert_eq!(
            state.drive(&mut first, reserve(1, "operation-1")),
            StoreProgress::Reserved
        );
        let mut retry = store("retry");
        assert_eq!(
            state.drive(&mut retry, reserve(1, "operation-1")),
            StoreProgress::ExistingPending
        );
        let mut o = obligation();
        o.lease = Some("other".into());
        assert_eq!(
            state.drive(&mut first, StoreCommand::VerifyPrior { obligation: o }),
            StoreProgress::Unknown
        );
    }
    #[test]
    fn missing_auth_and_unsafe_completion_fail_closed() {
        assert!(VerifiedTarget::authenticate("session-1".into(), |_| false).is_err());
        let mut state = FakeState::default();
        let mut first = store("first");
        assert_eq!(
            state.drive(&mut first, reserve(1, "operation-1")),
            StoreProgress::Reserved
        );
        assert_eq!(
            state.drive(
                &mut first,
                StoreCommand::Save {
                    sequence: 1,
                    obligation: obligation()
                }
            ),
            StoreProgress::Saved
        );
        assert_eq!(
            state.drive(
                &mut first,
                complete(
                    1,
                    "operation-1",
                    CallbackResult::Applied {
                        lease: "not-saved".into()
                    }
                )
            ),
            StoreProgress::Unknown
        );
    }
    #[test]
    fn failed_obligation_write_never_reports_saved() {
        let mut state = FakeState::default();
        let mut first = store("first");
        assert_eq!(
            state.drive(&mut first, reserve(1, "operation-1")),
            StoreProgress::Reserved
        );
        let command = StoreCommand::Save {
            sequence: 1,
            obligation: obligation(),
        };
        assert_eq!(first.poll(&command), StoreProgress::Waiting);
        for _ in 0..7 {
            first.advance(first.now_ms + 1, &mut |cmd| match &cmd {
                Command::Request { payload, .. } if payload["action"] == "set" => {
                    Err("lost write admission".into())
                }
                _ => state.send(cmd),
            });
        }
        assert_eq!(first.poll(&command), StoreProgress::Unknown);
        assert!(state.values.is_empty());
    }
}

use crate::virtual_callback::{self, VirtualObligation};
use crate::virtual_display::DisplayReference;

/// Virtual reference journal and callback receipts. The target and epoch have
/// the same authenticated-coordinator requirements as `StateDurableStore`.
pub struct VirtualDurableStateStore {
    epoch: VerifiedEpoch,
    target: VerifiedTarget,
    prefix: String,
    parent: Option<u64>,
    timeout_ms: u64,
    now_ms: u64,
    counter: u64,
    active: Option<VirtualActive>,
    ready: Option<(
        virtual_callback::StoreCommand,
        virtual_callback::StoreProgress,
    )>,
    receipt: Option<ActiveReceipt>,
    verified: Option<VirtualObligation>,
    saved: Option<VirtualObligation>,
    poisoned: bool,
    load: Option<LoadOperation>,
    load_ready: Option<Option<Value>>,
}
enum VirtualActive {
    Receipt {
        command: virtual_callback::StoreCommand,
        call: Box<PendingStoreOperation>,
    },
    Journal(Box<VirtualJournal>),
    Rejecting {
        command: virtual_callback::StoreCommand,
        journal: Box<VirtualJournal>,
    },
}
struct VirtualJournal {
    requested: virtual_callback::StoreCommand,
    key: String,
    stage: JournalStage,
    exchange: Exchange,
    attempts: u8,
    expected_revision: Option<u64>,
    verified: Option<VirtualObligation>,
    saved: Option<VirtualObligation>,
    deadline_ms: u64,
    broker_prefix: String,
}
impl VirtualDurableStateStore {
    pub fn start_load(&mut self) -> Result<(), &'static str> {
        if self.poisoned
            || self.active.is_some()
            || self.ready.is_some()
            || self.load.is_some()
            || self.load_ready.is_some()
        {
            return Err("store_busy_or_unavailable");
        }
        let prefix = self.next_prefix().ok_or("operation_exhausted")?;
        self.load = Some(LoadOperation::new(
            self.key(),
            prefix,
            self.parent,
            self.timeout_ms,
            self.now_ms,
        ));
        Ok(())
    }
    pub fn poll_load(&mut self) -> LoadProgress<VirtualObligation> {
        if self.poisoned {
            return LoadProgress::Unknown;
        }
        match self.load_ready.take() {
            Some(Some(value)) => match serde_json::from_value::<VirtualObligation>(value) {
                Ok(obligation) if valid_virtual(&obligation) => LoadProgress::Found(obligation),
                _ => {
                    self.poisoned = true;
                    LoadProgress::Unknown
                }
            },
            Some(None) => LoadProgress::Absent,
            None if self.load.is_some() => LoadProgress::Waiting,
            None => LoadProgress::Unknown,
        }
    }
    pub fn new(
        epoch: VerifiedEpoch,
        target: VerifiedTarget,
        prefix: String,
        parent: Option<u64>,
        timeout_ms: u64,
    ) -> Result<Self, &'static str> {
        if prefix.is_empty()
            || prefix.len() > 80
            || !prefix.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'_' | b'-' | b'/')
            })
            || !(1..=30_000).contains(&timeout_ms)
        {
            return Err("invalid_broker_operation");
        }
        Ok(Self {
            epoch,
            target,
            prefix,
            parent,
            timeout_ms,
            now_ms: 0,
            counter: 0,
            active: None,
            ready: None,
            receipt: None,
            verified: None,
            saved: None,
            poisoned: false,
            load: None,
            load_ready: None,
        })
    }
    fn key(&self) -> String {
        format!("virtual-obligation/v1/{}", self.target.0)
    }
    fn next_prefix(&mut self) -> Option<String> {
        self.counter = self.counter.checked_add(1)?;
        Some(format!("{}.{}", self.prefix, self.counter))
    }
    /// Drive at most one state-service request per call.
    pub fn advance(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) {
        if now_ms < self.now_ms {
            self.poisoned = true;
            return;
        }
        self.now_ms = now_ms;
        if let Some(mut load) = self.load.take() {
            match load.advance(now_ms, send) {
                LoadStep::Waiting => self.load = Some(load),
                LoadStep::Done(result) => match result {
                    Ok(value) => self.load_ready = Some(value),
                    Err(()) => self.poisoned = true,
                },
            }
            return;
        }
        let Some(active) = self.active.take() else {
            return;
        };
        match active {
            VirtualActive::Receipt { command, mut call } => match call.poll(now_ms, send) {
                Progress::Waiting => self.active = Some(VirtualActive::Receipt { command, call }),
                Progress::Done(outcome) => {
                    let result = match (&command, outcome) {
                        (
                            virtual_callback::StoreCommand::Reserve {
                                sequence,
                                operation_id,
                                request,
                            },
                            Outcome::Begun,
                        ) => {
                            self.receipt = Some(ActiveReceipt {
                                sequence: *sequence,
                                operation_id: operation_id.clone(),
                                request: request.clone(),
                            });
                            virtual_callback::StoreProgress::Reserved
                        }
                        (
                            virtual_callback::StoreCommand::Reserve { .. },
                            Outcome::RecoveryRequired(_),
                        ) => virtual_callback::StoreProgress::ExistingPending,
                        (
                            virtual_callback::StoreCommand::Reserve { .. },
                            Outcome::Completed(receipt),
                        ) => match receipt.state {
                            receipt_store::ReceiptState::Completed { result } => {
                                serde_json::from_value(result).map_or(
                                    virtual_callback::StoreProgress::Unknown,
                                    virtual_callback::StoreProgress::ExistingComplete,
                                )
                            }
                            _ => virtual_callback::StoreProgress::Unknown,
                        },
                        (
                            virtual_callback::StoreCommand::Complete { .. },
                            Outcome::Completed(_),
                        ) => virtual_callback::StoreProgress::Completed,
                        _ => virtual_callback::StoreProgress::Unknown,
                    };
                    self.ready = Some((command, result));
                }
            },
            VirtualActive::Journal(mut journal) => {
                match journal.advance(now_ms, self.timeout_ms, self.parent, send) {
                    VirtualJournalProgress::Waiting => {
                        self.active = Some(VirtualActive::Journal(journal))
                    }
                    VirtualJournalProgress::Done(result) => {
                        if result == virtual_callback::StoreProgress::Verified
                            && let virtual_callback::StoreCommand::VerifyPrior { obligation } =
                                &journal.requested
                        {
                            self.verified = Some(obligation.clone());
                        }
                        if result == virtual_callback::StoreProgress::Saved
                            && let virtual_callback::StoreCommand::Save { obligation, .. } =
                                &journal.requested
                        {
                            self.saved = Some(obligation.clone());
                        }
                        self.ready = Some((journal.requested, result));
                    }
                }
            }
            VirtualActive::Rejecting {
                command,
                mut journal,
            } => match journal.advance(now_ms, self.timeout_ms, self.parent, send) {
                VirtualJournalProgress::Waiting => {
                    self.active = Some(VirtualActive::Rejecting { command, journal })
                }
                VirtualJournalProgress::Done(virtual_callback::StoreProgress::Saved) => {
                    if let virtual_callback::StoreCommand::Save { obligation, .. } =
                        journal.requested
                    {
                        self.saved = Some(obligation);
                    }
                    match self.start_receipt_completion(command.clone()) {
                        Ok(active) => self.active = Some(active),
                        Err(()) => {
                            self.ready = Some((command, virtual_callback::StoreProgress::Unknown))
                        }
                    }
                }
                VirtualJournalProgress::Done(_) => {
                    self.ready = Some((command, virtual_callback::StoreProgress::Unknown))
                }
            },
        }
    }
    fn journal(&mut self, command: virtual_callback::StoreCommand) -> Result<VirtualJournal, ()> {
        let prefix = self.next_prefix().ok_or(())?;
        Ok(VirtualJournal::new(
            command,
            self.key(),
            prefix,
            self.parent,
            self.timeout_ms,
            self.now_ms,
            self.verified.clone(),
            self.saved.clone(),
        ))
    }
    fn start_receipt_completion(
        &mut self,
        command: virtual_callback::StoreCommand,
    ) -> Result<VirtualActive, ()> {
        let virtual_callback::StoreCommand::Complete {
            sequence,
            operation_id,
            result,
        } = &command
        else {
            return Err(());
        };
        let receipt = self.receipt.as_ref().ok_or(())?;
        if receipt.sequence != *sequence || receipt.operation_id != *operation_id {
            return Err(());
        }
        let request = receipt.request.clone();
        let result = serde_json::to_value(result).map_err(|_| ())?;
        let prefix = self.next_prefix().ok_or(())?;
        let call = PendingStoreOperation::new(
            Operation::Complete {
                epoch: self.epoch.clone(),
                sequence: *sequence,
                operation_id: operation_id.clone(),
                request,
                result,
            },
            prefix,
            self.parent,
            self.timeout_ms,
            self.now_ms,
        )
        .map_err(|_| ())?;
        Ok(VirtualActive::Receipt {
            command,
            call: Box::new(call),
        })
    }
    fn start(&mut self, command: &virtual_callback::StoreCommand) -> Result<VirtualActive, ()> {
        use virtual_callback::{CallbackResult, StoreCommand};
        match command {
            StoreCommand::Reserve {
                sequence,
                operation_id,
                request,
            } => {
                if self.receipt.is_some() {
                    return Err(());
                }
                let prefix = self.next_prefix().ok_or(())?;
                let call = PendingStoreOperation::new(
                    Operation::Begin {
                        epoch: self.epoch.clone(),
                        sequence: *sequence,
                        operation_id: operation_id.clone(),
                        request: request.clone(),
                    },
                    prefix,
                    self.parent,
                    self.timeout_ms,
                    self.now_ms,
                )
                .map_err(|_| ())?;
                Ok(VirtualActive::Receipt {
                    command: command.clone(),
                    call: Box::new(call),
                })
            }
            StoreCommand::VerifyPrior { obligation } => {
                if !valid_virtual(obligation) || obligation.reference_released {
                    return Err(());
                }
                Ok(VirtualActive::Journal(Box::new(
                    self.journal(command.clone())?,
                )))
            }
            StoreCommand::Save {
                sequence,
                obligation,
            } => {
                if self
                    .receipt
                    .as_ref()
                    .is_none_or(|r| r.sequence != *sequence)
                    || !valid_virtual(obligation)
                {
                    return Err(());
                }
                Ok(VirtualActive::Journal(Box::new(
                    self.journal(command.clone())?,
                )))
            }
            StoreCommand::Complete {
                sequence,
                operation_id,
                result,
            } => {
                let receipt = self.receipt.as_ref().ok_or(())?;
                if receipt.sequence != *sequence || receipt.operation_id != *operation_id {
                    return Err(());
                }
                let saved = self.saved.as_ref().ok_or(())?;
                match result {
                    CallbackResult::Prepared { candidate, .. } => {
                        let borrow = saved.borrow.as_ref().ok_or(())?;
                        if saved.reference_released
                            || candidate.resource.provider != crate::descriptor::PROVIDER
                            || candidate.resource.resource_id != saved.identity
                            || candidate.resource.incarnation
                                != virtual_callback::producer_incarnation(
                                    &saved.domain_id,
                                    &saved.identity,
                                    &borrow.observed_output,
                                )
                            || candidate.resource.revision != borrow.mutation_domain.revision
                            || candidate.resource.mutation_domain.as_deref()
                                != Some(saved.domain_id.as_str())
                            || candidate.geometry_revision != saved.geometry_revision
                            || candidate.mode.width != saved.width
                            || candidate.mode.height != saved.height
                            || candidate.mode.refresh_millihz != saved.refresh_millihz
                            || candidate.mode.hdr != saved.hdr_enabled
                        {
                            return Err(());
                        }
                        self.start_receipt_completion(command.clone())
                    }
                    CallbackResult::Released => {
                        if !saved.reference_released || saved.borrow.is_some() {
                            return Err(());
                        }
                        self.start_receipt_completion(command.clone())
                    }
                    CallbackResult::Rejected { .. } => {
                        if saved.borrow.is_some() || saved.reference_released {
                            return Err(());
                        }
                        let mut retired = saved.clone();
                        retired.reference_released = true;
                        let journal = self.journal(StoreCommand::Save {
                            sequence: *sequence,
                            obligation: retired,
                        })?;
                        Ok(VirtualActive::Rejecting {
                            command: command.clone(),
                            journal: Box::new(journal),
                        })
                    }
                }
            }
        }
    }
}
impl virtual_callback::DurableVirtualStore for VirtualDurableStateStore {
    fn poll(
        &mut self,
        command: &virtual_callback::StoreCommand,
    ) -> virtual_callback::StoreProgress {
        use virtual_callback::StoreProgress;
        if self.poisoned {
            return StoreProgress::Unknown;
        }
        if self.load.is_some() || self.load_ready.is_some() {
            return StoreProgress::Unknown;
        }
        if let Some((previous, result)) = self.ready.take() {
            if &previous != command {
                self.poisoned = true;
                return StoreProgress::Unknown;
            }
            if result == StoreProgress::Unknown {
                self.poisoned = true;
            }
            return result;
        }
        if let Some(active) = &self.active {
            let current = match active {
                VirtualActive::Receipt { command, .. }
                | VirtualActive::Rejecting { command, .. } => command,
                VirtualActive::Journal(journal) => &journal.requested,
            };
            if current != command {
                self.poisoned = true;
                return StoreProgress::Unknown;
            }
            return StoreProgress::Waiting;
        }
        match self.start(command) {
            Ok(active) => {
                self.active = Some(active);
                StoreProgress::Waiting
            }
            Err(()) => {
                self.poisoned = true;
                StoreProgress::Unknown
            }
        }
    }
}
impl VirtualJournal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        requested: virtual_callback::StoreCommand,
        key: String,
        prefix: String,
        parent: Option<u64>,
        timeout_ms: u64,
        now_ms: u64,
        verified: Option<VirtualObligation>,
        saved: Option<VirtualObligation>,
    ) -> Self {
        Self {
            requested,
            key: key.clone(),
            stage: JournalStage::Read,
            exchange: Exchange {
                command: Command::Request {
                    service: SERVICE.into(),
                    payload: json!({"action":"get","key":key}),
                    timeout_ms,
                    operation_id: format!("{prefix}.read.0"),
                    parent,
                },
                request_id: None,
                result: None,
                failures: 0,
                uncertain: false,
            },
            attempts: 0,
            expected_revision: None,
            verified,
            saved,
            deadline_ms: now_ms.saturating_add(timeout_ms),
            broker_prefix: prefix,
        }
    }
    fn restart_read(&mut self, timeout_ms: u64, parent: Option<u64>) {
        self.stage = JournalStage::Read;
        self.exchange = Exchange {
            command: Command::Request {
                service: SERVICE.into(),
                payload: json!({"action":"get","key":self.key}),
                timeout_ms,
                operation_id: format!("{}.read.{}", self.broker_prefix, self.attempts),
                parent,
            },
            request_id: None,
            result: None,
            failures: 0,
            uncertain: false,
        };
    }
    fn advance(
        &mut self,
        now_ms: u64,
        timeout_ms: u64,
        parent: Option<u64>,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> VirtualJournalProgress {
        use virtual_callback::StoreProgress;
        if now_ms >= self.deadline_ms || self.exchange.failures >= MAX_FAILURES {
            return VirtualJournalProgress::Done(StoreProgress::Unknown);
        }
        if let Some(id) = self.exchange.request_id {
            if self.exchange.result.is_some() {
                match send(Command::ReleaseResult { request: id }) {
                    Ok(Response::Ok) => {
                        let payload = self.exchange.result.take().expect("result");
                        self.consume(payload, timeout_ms, parent)
                    }
                    _ => {
                        self.exchange.failures += 1;
                        VirtualJournalProgress::Waiting
                    }
                }
            } else {
                match send(Command::TakeResult { request: id }) {
                    Ok(Response::Pending) => VirtualJournalProgress::Waiting,
                    Ok(Response::Result { payload }) => {
                        self.exchange.result = Some(payload);
                        VirtualJournalProgress::Waiting
                    }
                    _ => {
                        self.exchange.failures += 1;
                        VirtualJournalProgress::Waiting
                    }
                }
            }
        } else {
            match send(self.exchange.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.exchange.request_id = Some(id);
                    self.exchange.failures = 0;
                    VirtualJournalProgress::Waiting
                }
                Ok(Response::Error { .. }) if !self.exchange.uncertain => {
                    VirtualJournalProgress::Done(StoreProgress::Unknown)
                }
                _ => {
                    self.exchange.uncertain = true;
                    self.exchange.failures += 1;
                    VirtualJournalProgress::Waiting
                }
            }
        }
    }
    fn consume(
        &mut self,
        payload: Value,
        timeout_ms: u64,
        parent: Option<u64>,
    ) -> VirtualJournalProgress {
        use virtual_callback::{StoreCommand, StoreProgress};
        let Some(ok) = payload.get("ok").and_then(Value::as_bool) else {
            return VirtualJournalProgress::Done(StoreProgress::Unknown);
        };
        if !ok {
            if matches!(self.stage, JournalStage::Write)
                && payload.pointer("/error/code").and_then(Value::as_str)
                    == Some("revision_conflict")
            {
                self.attempts += 1;
                if self.attempts < MAX_FAILURES {
                    self.restart_read(timeout_ms, parent);
                    return VirtualJournalProgress::Waiting;
                }
            }
            return VirtualJournalProgress::Done(StoreProgress::Unknown);
        }
        match self.stage {
            JournalStage::Write => {
                if payload.get("revision").and_then(Value::as_u64) == self.expected_revision {
                    VirtualJournalProgress::Done(StoreProgress::Saved)
                } else {
                    VirtualJournalProgress::Done(StoreProgress::Unknown)
                }
            }
            JournalStage::Read => {
                let Some(revision) = payload.get("revision").and_then(Value::as_u64) else {
                    return VirtualJournalProgress::Done(StoreProgress::Unknown);
                };
                let Some(found) = payload.get("found").and_then(Value::as_bool) else {
                    return VirtualJournalProgress::Done(StoreProgress::Unknown);
                };
                let Some(value) = payload.get("value") else {
                    return VirtualJournalProgress::Done(StoreProgress::Unknown);
                };
                let current = if found {
                    let Ok(value) = serde_json::from_value::<VirtualObligation>(value.clone())
                    else {
                        return VirtualJournalProgress::Done(StoreProgress::Unknown);
                    };
                    if !valid_virtual(&value) {
                        return VirtualJournalProgress::Done(StoreProgress::Unknown);
                    }
                    Some(value)
                } else if value.is_null() {
                    None
                } else {
                    return VirtualJournalProgress::Done(StoreProgress::Unknown);
                };
                match &self.requested {
                    StoreCommand::VerifyPrior { obligation } => {
                        if current.as_ref() == Some(obligation) && !obligation.reference_released {
                            VirtualJournalProgress::Done(StoreProgress::Verified)
                        } else {
                            VirtualJournalProgress::Done(StoreProgress::Unknown)
                        }
                    }
                    StoreCommand::Save { obligation, .. } => {
                        if !self.allowed_save(current.as_ref(), obligation) {
                            return VirtualJournalProgress::Done(StoreProgress::Unknown);
                        }
                        let Some(next) = revision.checked_add(1) else {
                            return VirtualJournalProgress::Done(StoreProgress::Unknown);
                        };
                        self.expected_revision = Some(next);
                        self.stage = JournalStage::Write;
                        self.exchange = Exchange {
                            command: Command::Request {
                                service: SERVICE.into(),
                                payload: json!({"action":"set","key":self.key,"value":obligation,"expected_revision":revision}),
                                timeout_ms,
                                operation_id: format!(
                                    "{}.write.{}",
                                    self.broker_prefix, self.attempts
                                ),
                                parent,
                            },
                            request_id: None,
                            result: None,
                            failures: 0,
                            uncertain: false,
                        };
                        VirtualJournalProgress::Waiting
                    }
                    _ => VirtualJournalProgress::Done(StoreProgress::Unknown),
                }
            }
        }
    }
    fn allowed_save(&self, current: Option<&VirtualObligation>, next: &VirtualObligation) -> bool {
        if !valid_virtual(next) {
            return false;
        }
        let initial = next.borrow.is_none() && !next.reference_released;
        let Some(current) = current else {
            return initial && self.saved.is_none() && self.verified.is_none();
        };
        if current.reference_released && initial && self.saved.is_none() && self.verified.is_none()
        {
            return true;
        }
        if self.saved.as_ref() != Some(current) && self.verified.as_ref() != Some(current) {
            return false;
        }
        if current == next {
            return true;
        }
        let mut normalized = next.clone();
        normalized.borrow = current.borrow.clone();
        normalized.reference_released = current.reference_released;
        if normalized != *current || current.reference_released {
            return false;
        }
        if let (Some(old), Some(new)) = (&current.borrow, &next.borrow) {
            return !next.reference_released
                && old.borrow_id == new.borrow_id
                && old.observed_output == new.observed_output
                && old.mutation_domain.id == new.mutation_domain.id
                && old.mutation_domain.scope == new.mutation_domain.scope
                && new.mutation_domain.revision >= old.mutation_domain.revision
                && new.mutation_domain.pending_mutations == 0
                && new.mutation_domain.borrowers > 0;
        }
        (current.borrow.is_none() && next.borrow.is_some() && !next.reference_released)
            || (current.borrow.is_some() && next.borrow.is_none() && !next.reference_released)
            || (current.borrow.is_none() && next.borrow.is_none() && next.reference_released)
    }
}
enum VirtualJournalProgress {
    Waiting,
    Done(virtual_callback::StoreProgress),
}
fn valid_virtual(value: &VirtualObligation) -> bool {
    let reference = DisplayReference {
        identity: value.identity.clone(),
        reference_id: value.reference_id.clone(),
    };
    if value.provider_service != crate::virtual_display::SERVICE
        || reference.validate().is_err()
        || !(320..=7680).contains(&value.width)
        || !(200..=4320).contains(&value.height)
        || !(1000..=1_000_000).contains(&value.refresh_millihz)
        || value.name.is_empty()
        || value.name.len() > 31
        || !value
            .name
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
        || value.scale.is_some_and(|v| v != 0)
        || !matches!(value.layout.as_str(), "extended" | "exclusive")
        || value.domain_id.is_empty()
        || value.domain_id.len() > 128
        || !value.domain_id.bytes().all(|b| b.is_ascii_graphic())
        || value.geometry_revision == 0
        || (value.reference_released && value.borrow.is_some())
    {
        return false;
    }
    if let Some(borrow) = &value.borrow
        && (borrow.borrow_id.is_empty()
            || borrow.borrow_id.len() > 128
            || !borrow.borrow_id.bytes().all(|b| b.is_ascii_graphic())
            || borrow.mutation_domain.id != value.domain_id
            || borrow.observed_output.width != value.width
            || borrow.observed_output.height != value.height
            || borrow.observed_output.refresh_millihz != value.refresh_millihz)
    {
        return false;
    }
    true
}

#[cfg(test)]
mod virtual_tests {
    use super::*;
    use crate::virtual_callback::{
        CallbackResult, DurableVirtualStore, StoreCommand, StoreProgress,
    };
    use crate::virtual_display::{DisplayBorrow, MutationDomain, ObservedOutput};
    fn epoch() -> VerifiedEpoch {
        VerifiedEpoch::authenticate("epoch-a".into(), |_| true).unwrap()
    }
    fn store(prefix: &str) -> VirtualDurableStateStore {
        VirtualDurableStateStore::new(
            epoch(),
            VerifiedTarget::authenticate("session-1".into(), |_| true).unwrap(),
            prefix.into(),
            None,
            30_000,
        )
        .unwrap()
    }
    pub(super) fn obligation() -> VirtualObligation {
        VirtualObligation {
            provider_service: crate::virtual_display::SERVICE.into(),
            identity: "9c1d707f-7229-4fc4-b6e2-91f80c626a09".into(),
            reference_id: "ref-1".into(),
            width: 1920,
            height: 1080,
            refresh_millihz: 60_000,
            name: "Amaterasu".into(),
            hdr_enabled: false,
            scale: None,
            layout: "extended".into(),
            domain_id: "desktop".into(),
            domain_revision: 1,
            geometry_revision: 1,
            borrow: None,
            reference_released: false,
        }
    }
    fn borrow() -> DisplayBorrow {
        DisplayBorrow {
            borrow_id: "borrow-1".into(),
            observed_output: ObservedOutput {
                version: 1,
                protocol: "wayland".into(),
                compositor_id: "kwin".into(),
                registry_global: 1,
                output_name: "virtual-1".into(),
                width: 1920,
                height: 1080,
                refresh_millihz: 60_000,
            },
            mutation_domain: MutationDomain {
                id: "desktop".into(),
                revision: 2,
                borrowers: 1,
                pending_mutations: 0,
                scope: "desktop".into(),
            },
        }
    }
    fn drive(
        state: &mut super::tests::FakeState,
        store: &mut VirtualDurableStateStore,
        command: StoreCommand,
    ) -> StoreProgress {
        for _ in 0..60 {
            let result = store.poll(&command);
            if result != StoreProgress::Waiting {
                return result;
            }
            store.advance(store.now_ms + 1, &mut |cmd| state.send(cmd));
        }
        panic!("stuck");
    }
    fn reserve(sequence: u64, id: &str) -> StoreCommand {
        StoreCommand::Reserve {
            sequence,
            operation_id: id.into(),
            request: json!({"id":id}),
        }
    }
    #[test]
    fn virtual_borrow_and_release_are_separately_durable() {
        let mut state = super::tests::FakeState::default();
        let mut prepare = store("virtual-prepare");
        let mut o = obligation();
        assert_eq!(
            drive(&mut state, &mut prepare, reserve(1, "op-1")),
            StoreProgress::Reserved
        );
        assert_eq!(
            drive(
                &mut state,
                &mut prepare,
                StoreCommand::Save {
                    sequence: 1,
                    obligation: o.clone()
                }
            ),
            StoreProgress::Saved
        );
        o.borrow = Some(borrow());
        assert_eq!(
            drive(
                &mut state,
                &mut prepare,
                StoreCommand::Save {
                    sequence: 1,
                    obligation: o.clone()
                }
            ),
            StoreProgress::Saved
        );
        o.borrow.as_mut().unwrap().mutation_domain.revision = 3;
        o.borrow.as_mut().unwrap().mutation_domain.borrowers = 2;
        assert_eq!(
            drive(
                &mut state,
                &mut prepare,
                StoreCommand::Save {
                    sequence: 1,
                    obligation: o.clone()
                }
            ),
            StoreProgress::Saved
        );
        let candidate = serde_json::from_value(json!({"capture_provider":"capture","selector_schema":"selector","selector":{},"resource":{"provider":"nonary.display-settings","resource_id":o.identity,"incarnation":virtual_callback::producer_incarnation(&o.domain_id, &o.identity, &o.borrow.as_ref().unwrap().observed_output),"revision":3,"execution_domain":"desktop","mutation_domain":"desktop"},"mode":{"width":1920,"height":1080,"refresh_millihz":60000,"hdr":false},"plan_revision":1,"geometry_revision":1,"generation":1,"fallback":"forbidden"})).unwrap();
        assert_eq!(
            drive(
                &mut state,
                &mut prepare,
                StoreCommand::Complete {
                    sequence: 1,
                    operation_id: "op-1".into(),
                    result: CallbackResult::Prepared {
                        candidate: Box::new(candidate),
                        obligations: vec![]
                    }
                }
            ),
            StoreProgress::Completed
        );
        let mut release = store("virtual-release");
        assert_eq!(
            drive(&mut state, &mut release, reserve(2, "op-2")),
            StoreProgress::Reserved
        );
        assert_eq!(
            drive(
                &mut state,
                &mut release,
                StoreCommand::VerifyPrior {
                    obligation: o.clone()
                }
            ),
            StoreProgress::Verified
        );
        o.borrow = None;
        assert_eq!(
            drive(
                &mut state,
                &mut release,
                StoreCommand::Save {
                    sequence: 2,
                    obligation: o.clone()
                }
            ),
            StoreProgress::Saved
        );
        o.reference_released = true;
        assert_eq!(
            drive(
                &mut state,
                &mut release,
                StoreCommand::Save {
                    sequence: 2,
                    obligation: o
                }
            ),
            StoreProgress::Saved
        );
        assert_eq!(
            drive(
                &mut state,
                &mut release,
                StoreCommand::Complete {
                    sequence: 2,
                    operation_id: "op-2".into(),
                    result: CallbackResult::Released
                }
            ),
            StoreProgress::Completed
        );
    }
    #[test]
    fn borrowed_prior_must_match_and_unknown_never_saves() {
        let mut state = super::tests::FakeState::default();
        let mut prepare = store("prepare");
        let mut o = obligation();
        assert_eq!(
            drive(&mut state, &mut prepare, reserve(1, "op-1")),
            StoreProgress::Reserved
        );
        assert_eq!(
            drive(
                &mut state,
                &mut prepare,
                StoreCommand::Save {
                    sequence: 1,
                    obligation: o.clone()
                }
            ),
            StoreProgress::Saved
        );
        o.reference_id = "foreign".into();
        let mut validator = store("validator");
        assert_eq!(
            drive(
                &mut state,
                &mut validator,
                StoreCommand::VerifyPrior { obligation: o }
            ),
            StoreProgress::Unknown
        );
    }
    #[test]
    fn borrow_refresh_rejects_identity_change_or_pending_mutation() {
        let mut original = obligation();
        original.borrow = Some(borrow());
        let journal = VirtualJournal::new(
            StoreCommand::Save {
                sequence: 1,
                obligation: original.clone(),
            },
            "key".into(),
            "prefix".into(),
            None,
            1000,
            0,
            None,
            Some(original.clone()),
        );
        let mut changed = original.clone();
        changed.borrow.as_mut().unwrap().borrow_id = "foreign".into();
        assert!(!journal.allowed_save(Some(&original), &changed));
        changed = original.clone();
        changed
            .borrow
            .as_mut()
            .unwrap()
            .mutation_domain
            .pending_mutations = 1;
        assert!(!journal.allowed_save(Some(&original), &changed));
        changed = original.clone();
        changed.borrow.as_mut().unwrap().mutation_domain.revision -= 1;
        assert!(!journal.allowed_save(Some(&original), &changed));
    }
    #[test]
    fn definitive_rejection_closes_uncreated_intent_before_receipt() {
        let mut state = super::tests::FakeState::default();
        let mut prepare = store("prepare");
        let o = obligation();
        assert_eq!(
            drive(&mut state, &mut prepare, reserve(1, "op-1")),
            StoreProgress::Reserved
        );
        assert_eq!(
            drive(
                &mut state,
                &mut prepare,
                StoreCommand::Save {
                    sequence: 1,
                    obligation: o
                }
            ),
            StoreProgress::Saved
        );
        assert_eq!(
            drive(
                &mut state,
                &mut prepare,
                StoreCommand::Complete {
                    sequence: 1,
                    operation_id: "op-1".into(),
                    result: CallbackResult::Rejected {
                        reason: "denied".into()
                    }
                }
            ),
            StoreProgress::Completed
        );
        let mut next = store("next");
        assert_eq!(
            drive(&mut state, &mut next, reserve(2, "op-2")),
            StoreProgress::Reserved
        );
        let mut o = obligation();
        o.reference_id = "ref-2".into();
        assert_eq!(
            drive(
                &mut state,
                &mut next,
                StoreCommand::Save {
                    sequence: 2,
                    obligation: o
                }
            ),
            StoreProgress::Saved
        );
    }
}

/// Read-only discovery does not itself authorize applying or restoring a
/// resource. `Found` is the exact durable journal for the verified target.
#[derive(Clone, Debug, PartialEq)]
pub enum LoadProgress<T> {
    Waiting,
    Found(T),
    Absent,
    Unknown,
}
struct LoadOperation {
    exchange: Exchange,
    deadline_ms: u64,
}
enum LoadStep {
    Waiting,
    Done(Result<Option<Value>, ()>),
}
impl LoadOperation {
    fn new(key: String, prefix: String, parent: Option<u64>, timeout_ms: u64, now_ms: u64) -> Self {
        Self {
            exchange: Exchange {
                command: Command::Request {
                    service: SERVICE.into(),
                    payload: json!({"action":"get","key":key}),
                    timeout_ms,
                    operation_id: format!("{prefix}.load"),
                    parent,
                },
                request_id: None,
                result: None,
                failures: 0,
                uncertain: false,
            },
            deadline_ms: now_ms.saturating_add(timeout_ms),
        }
    }
    fn advance(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> LoadStep {
        if now_ms >= self.deadline_ms || self.exchange.failures >= MAX_FAILURES {
            return LoadStep::Done(Err(()));
        }
        if let Some(id) = self.exchange.request_id {
            if self.exchange.result.is_some() {
                match send(Command::ReleaseResult { request: id }) {
                    Ok(Response::Ok) => {
                        let result = self.exchange.result.take().expect("result");
                        let value = match (
                            result.get("ok").and_then(Value::as_bool),
                            result.get("found").and_then(Value::as_bool),
                            result.get("value"),
                            result.get("revision").and_then(Value::as_u64),
                        ) {
                            (Some(true), Some(true), Some(value), Some(_)) if !value.is_null() => {
                                Ok(Some(value.clone()))
                            }
                            (Some(true), Some(false), Some(Value::Null), Some(_)) => Ok(None),
                            _ => Err(()),
                        };
                        LoadStep::Done(value)
                    }
                    _ => {
                        self.exchange.failures += 1;
                        LoadStep::Waiting
                    }
                }
            } else {
                match send(Command::TakeResult { request: id }) {
                    Ok(Response::Pending) => LoadStep::Waiting,
                    Ok(Response::Result { payload }) => {
                        self.exchange.result = Some(payload);
                        LoadStep::Waiting
                    }
                    _ => {
                        self.exchange.failures += 1;
                        LoadStep::Waiting
                    }
                }
            }
        } else {
            match send(self.exchange.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.exchange.request_id = Some(id);
                    self.exchange.failures = 0;
                    LoadStep::Waiting
                }
                Ok(Response::Error { .. }) if !self.exchange.uncertain => LoadStep::Done(Err(())),
                _ => {
                    self.exchange.uncertain = true;
                    self.exchange.failures += 1;
                    LoadStep::Waiting
                }
            }
        }
    }
}
fn valid_physical(value: &RecoveryObligation) -> bool {
    RecoveryObligation::new(
        value.operation_id.clone(),
        value.configuration.clone(),
        value.topology_revision.clone(),
    )
    .is_ok()
        && value.lease.as_deref().is_none_or(|lease| {
            !lease.is_empty() && lease.len() <= 256 && lease.bytes().all(|b| b.is_ascii_graphic())
        })
        && (!value.restored || value.lease.is_some())
}

#[cfg(test)]
mod load_tests {
    use super::*;
    use std::collections::VecDeque;
    fn context() -> (VerifiedEpoch, VerifiedTarget) {
        (
            VerifiedEpoch::authenticate("epoch".into(), |_| true).unwrap(),
            VerifiedTarget::authenticate("session-x".into(), |_| true).unwrap(),
        )
    }
    #[test]
    fn physical_discovery_reads_only_verified_key_and_distinguishes_absent() {
        let (epoch, target) = context();
        let mut store =
            StateDurableStore::new(epoch, target, "load-physical".into(), None, 1000).unwrap();
        store.start_load().unwrap();
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 1 }),
            Ok(Response::Result {
                payload: json!({"ok":true,"revision":0,"found":false,"value":null}),
            }),
            Ok(Response::Ok),
        ]);
        let mut commands = Vec::new();
        for tick in 0..3 {
            store.advance(tick, &mut |cmd| {
                commands.push(cmd);
                replies.pop_front().unwrap()
            });
        }
        assert_eq!(store.poll_load(), LoadProgress::Absent);
        assert!(
            matches!(&commands[0],Command::Request { payload,.. } if payload["key"]=="physical-obligation/v1/session-x")
        );
    }
    #[test]
    fn virtual_discovery_rejects_invalid_journal_and_never_guesses_a_key() {
        let (epoch, target) = context();
        let mut store =
            VirtualDurableStateStore::new(epoch, target, "load-virtual".into(), None, 1000)
                .unwrap();
        store.start_load().unwrap();
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 1 }),
            Ok(Response::Result {
                payload: json!({"ok":true,"revision":1,"found":true,"value":{"identity":"bogus"}}),
            }),
            Ok(Response::Ok),
        ]);
        let mut commands = Vec::new();
        for tick in 0..3 {
            store.advance(tick, &mut |cmd| {
                commands.push(cmd);
                replies.pop_front().unwrap()
            });
        }
        assert_eq!(store.poll_load(), LoadProgress::Unknown);
        assert!(
            matches!(&commands[0],Command::Request { payload,.. } if payload["key"]=="virtual-obligation/v1/session-x")
        );
    }
    #[test]
    fn virtual_discovery_returns_exact_persisted_obligation() {
        let (epoch, target) = context();
        let mut store =
            VirtualDurableStateStore::new(epoch, target, "load-found".into(), None, 1000).unwrap();
        let expected = super::virtual_tests::obligation();
        store.start_load().unwrap();
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 1 }),
            Ok(Response::Result {
                payload: json!({"ok":true,"revision":7,"found":true,"value":expected}),
            }),
            Ok(Response::Ok),
        ]);
        for tick in 0..3 {
            store.advance(tick, &mut |_| replies.pop_front().unwrap());
        }
        assert_eq!(store.poll_load(), LoadProgress::Found(expected));
    }
}

/// A read-only lookup of provider-owned state before the current coordinator
/// epoch is established. The caller argument must be the authenticated broker
/// caller, never a field from the request body. `Found` still requires verifying
/// the returned original request with the selected coordinator before use.
pub struct PriorReceiptLookup {
    sequence: u64,
    operation_id: String,
    exchange: Exchange,
    deadline_ms: u64,
    finished: Option<PriorReceiptProgress>,
}
#[derive(Clone, Debug, PartialEq)]
pub enum PriorReceiptProgress {
    Waiting,
    Found {
        receipt: receipt_store::Receipt,
        request: Box<amaterasu_module_sdk::extension_api::ProviderRequest>,
    },
    Expired,
    Unknown,
}
impl PriorReceiptLookup {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        caller: &str,
        sequence: u64,
        operation_id: String,
        prefix: String,
        parent: Option<u64>,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        if caller != "amaterasu.session-lifecycle"
            || sequence == 0
            || operation_id.is_empty()
            || operation_id.len() > 128
            || !operation_id.bytes().all(|b| b.is_ascii_graphic())
            || prefix.is_empty()
            || prefix.len() > 100
            || !prefix.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'_' | b'-' | b'/')
            })
            || !(1..=30_000).contains(&timeout_ms)
        {
            return Err("unauthorized_or_invalid_lookup");
        }
        Ok(Self {
            sequence,
            operation_id,
            exchange: Exchange {
                command: Command::Request {
                    service: SERVICE.into(),
                    payload: json!({"action":"collection_get","collection":"display-settings/operation-receipts-v2","key":format!("{sequence:020}")}),
                    timeout_ms,
                    operation_id: format!("{prefix}.lookup"),
                    parent,
                },
                request_id: None,
                result: None,
                failures: 0,
                uncertain: false,
            },
            deadline_ms: now_ms.saturating_add(timeout_ms),
            finished: None,
        })
    }
    pub fn request_id(&self) -> Option<u64> {
        self.exchange.request_id
    }
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> PriorReceiptProgress {
        if let Some(progress) = &self.finished {
            return progress.clone();
        }
        if now_ms >= self.deadline_ms || self.exchange.failures >= MAX_FAILURES {
            return self.done(PriorReceiptProgress::Unknown);
        }
        if let Some(id) = self.exchange.request_id {
            if self.exchange.result.is_some() {
                match send(Command::ReleaseResult { request: id }) {
                    Ok(Response::Ok) => {
                        let payload = self.exchange.result.take().expect("result");
                        let result = self.parse(payload);
                        self.done(result)
                    }
                    _ => {
                        self.exchange.failures += 1;
                        PriorReceiptProgress::Waiting
                    }
                }
            } else {
                match send(Command::TakeResult { request: id }) {
                    Ok(Response::Pending) => PriorReceiptProgress::Waiting,
                    Ok(Response::Result { payload }) => {
                        self.exchange.result = Some(payload);
                        PriorReceiptProgress::Waiting
                    }
                    _ => {
                        self.exchange.failures += 1;
                        PriorReceiptProgress::Waiting
                    }
                }
            }
        } else {
            match send(self.exchange.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.exchange.request_id = Some(id);
                    self.exchange.failures = 0;
                    PriorReceiptProgress::Waiting
                }
                Ok(Response::Error { .. }) if !self.exchange.uncertain => {
                    self.done(PriorReceiptProgress::Unknown)
                }
                _ => {
                    self.exchange.uncertain = true;
                    self.exchange.failures += 1;
                    PriorReceiptProgress::Waiting
                }
            }
        }
    }
    fn parse(&self, payload: Value) -> PriorReceiptProgress {
        if payload.get("ok").and_then(Value::as_bool) != Some(true) {
            return PriorReceiptProgress::Unknown;
        }
        let (Some(revision), Some(found), Some(count), Some(metadata)) = (
            payload.get("revision").and_then(Value::as_u64),
            payload.get("found").and_then(Value::as_bool),
            payload.get("count").and_then(Value::as_u64),
            payload.get("metadata"),
        ) else {
            return PriorReceiptProgress::Unknown;
        };
        if !found || revision == 0 {
            return PriorReceiptProgress::Unknown;
        }
        let (Some(version), Some(epoch), Some(low), Some(high), Some(pending)) = (
            metadata.get("format_version").and_then(Value::as_u64),
            metadata.get("epoch").and_then(Value::as_str),
            metadata.get("low").and_then(Value::as_u64),
            metadata.get("high").and_then(Value::as_u64),
            metadata.get("pending").and_then(Value::as_u64),
        ) else {
            return PriorReceiptProgress::Unknown;
        };
        if epoch.is_empty()
            || epoch.len() > 80
            || !epoch.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'_' | b'-' | b'/')
            })
            || low > high
            || pending > 1
            || pending > count
        {
            return PriorReceiptProgress::Unknown;
        }
        if self.sequence > high {
            return PriorReceiptProgress::Unknown;
        }
        let retained = match version {
            2 if metadata.as_object().is_some_and(|obj| obj.len() == 5)
                && high - low <= 64
                && count == high - low =>
            {
                true
            }
            3 => {
                let Some(object) = metadata.as_object() else {
                    return PriorReceiptProgress::Unknown;
                };
                if (object.len() != 5 && object.len() != 6)
                    || object.keys().any(|key| {
                        !matches!(
                            key.as_str(),
                            "format_version" | "epoch" | "low" | "high" | "pending" | "sequences"
                        )
                    })
                {
                    return PriorReceiptProgress::Unknown;
                }
                let sequences: Vec<u64> = match object.get("sequences") {
                    None => Vec::new(),
                    Some(value) => match serde_json::from_value(value.clone()) {
                        Ok(sequences) => sequences,
                        Err(_) => return PriorReceiptProgress::Unknown,
                    },
                };
                if sequences.len() > 64
                    || sequences.len() as u64 != count
                    || sequences
                        .iter()
                        .any(|sequence| *sequence <= low || *sequence > high)
                    || sequences.windows(2).any(|pair| pair[0] >= pair[1])
                    || sequences.last().copied().unwrap_or(low) != high
                {
                    return PriorReceiptProgress::Unknown;
                }
                sequences.binary_search(&self.sequence).is_ok()
            }
            _ => return PriorReceiptProgress::Unknown,
        };
        if self.sequence <= low {
            return PriorReceiptProgress::Expired;
        }
        if !retained {
            return if payload.get("value").is_some_and(Value::is_null) {
                PriorReceiptProgress::Expired
            } else {
                PriorReceiptProgress::Unknown
            };
        }
        let Some(value) = payload.get("value") else {
            return PriorReceiptProgress::Unknown;
        };
        let Ok(receipt) = serde_json::from_value::<receipt_store::Receipt>(value.clone()) else {
            return PriorReceiptProgress::Unknown;
        };
        if receipt.operation_id != self.operation_id {
            return PriorReceiptProgress::Unknown;
        }
        let Ok(request) = serde_json::from_value::<
            amaterasu_module_sdk::extension_api::ProviderRequest,
        >(receipt.request.clone()) else {
            return PriorReceiptProgress::Unknown;
        };
        if request.operation_id != self.operation_id
            || request.provider_sequence != self.sequence
            || request.operation
                != amaterasu_module_sdk::extension_api::ProviderOperation::LifecycleCallback
            || amaterasu_module_sdk::extension_api::validate_provider_request(&request).is_err()
        {
            return PriorReceiptProgress::Unknown;
        }
        PriorReceiptProgress::Found {
            receipt,
            request: Box::new(request),
        }
    }
    fn done(&mut self, result: PriorReceiptProgress) -> PriorReceiptProgress {
        self.finished = Some(result.clone());
        result
    }
}

#[cfg(test)]
mod prior_receipt_tests {
    use super::*;
    use std::collections::VecDeque;
    fn saved_request() -> Value {
        json!({"provider_sequence":9,"operation":"lifecycle_callback","version":1,"transition_id":"transition-9","operation_id":"operation-9","target":{"kind":"session","host_epoch":"old-epoch","session_id":"session-1","generation":1},"phase":"session.prepare","settings_revision":"settings-1","settings":{},"intent":null,"reason":null,"requested_video":null,"consumer_requirements":{"execution_domain":"desktop","capture_providers":["capture"],"selector_schemas":["selector"]},"remaining_ms":1000,"plan_revision":1,"admission_id":"admission-1","approved_plan":{"plan_id":"plan-1","revision":1,"resources":[],"mutation_domains":[],"required_capabilities":[],"constraints":{},"obligations":[],"affected_consumers":[],"consumer_change":"live","candidate_constraint":null,"allowed_degradation":[]}})
    }
    fn response(value: Value) -> Value {
        json!({"ok":true,"revision":1,"found":true,"count":1,"metadata":{"format_version":2,"epoch":"new-epoch","low":8,"high":9,"pending":1},"value":value})
    }
    fn run(payload: Value) -> PriorReceiptProgress {
        let mut lookup = PriorReceiptLookup::new(
            "amaterasu.session-lifecycle",
            9,
            "operation-9".into(),
            "prior".into(),
            None,
            1000,
            0,
        )
        .unwrap();
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 1 }),
            Ok(Response::Result { payload }),
            Ok(Response::Ok),
        ]);
        for tick in 0..3 {
            let progress = lookup.poll(tick, &mut |_| replies.pop_front().unwrap());
            if tick == 2 {
                return progress;
            }
        }
        unreachable!()
    }
    #[test]
    fn exact_saved_callback_is_recovered_without_trusting_epoch_payload() {
        let request = saved_request();
        let value =
            json!({"operation_id":"operation-9","request":request,"state":{"state":"pending"}});
        match run(response(value)) {
            PriorReceiptProgress::Found { receipt, request } => {
                assert_eq!(receipt.operation_id, "operation-9");
                assert_eq!(request.provider_sequence, 9);
                assert!(
                    matches!(request.target,amaterasu_module_sdk::extension_api::LifecycleTarget::Session { host_epoch,.. } if host_epoch=="old-epoch")
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    #[test]
    fn lookup_rejects_wrong_caller_identity_mismatch_and_retired_sequence() {
        assert!(
            PriorReceiptLookup::new(
                "foreign",
                9,
                "operation-9".into(),
                "prior".into(),
                None,
                1000,
                0
            )
            .is_err()
        );
        let value =
            json!({"operation_id":"other","request":saved_request(),"state":{"state":"pending"}});
        assert_eq!(run(response(value)), PriorReceiptProgress::Unknown);
        let expired = json!({"ok":true,"revision":2,"found":true,"count":0,"metadata":{"format_version":2,"epoch":"new-epoch","low":9,"high":9,"pending":0},"value":null});
        assert_eq!(run(expired), PriorReceiptProgress::Expired);
    }
    #[test]
    fn prior_lookup_accepts_sparse_metadata_and_expires_unseen_gaps() {
        let value = json!({"operation_id":"operation-9","request":saved_request(),"state":{"state":"pending"}});
        let metadata = json!({"format_version":3,"epoch":"new-epoch","low":1,"high":12,"pending":1,"sequences":[5,9,12]});
        let payload = json!({"ok":true,"revision":3,"found":true,"count":3,"metadata":metadata,"value":value});
        assert!(matches!(run(payload), PriorReceiptProgress::Found { .. }));
        let gap = json!({"ok":true,"revision":3,"found":true,"count":2,"metadata":{"format_version":3,"epoch":"new-epoch","low":1,"high":12,"pending":0,"sequences":[5,12]},"value":null});
        assert_eq!(run(gap), PriorReceiptProgress::Expired);
    }
}

#[cfg(test)]
mod callback_retirement_tests {
    use super::*;
    use crate::virtual_callback::{self, EffectGuard, EffectKind, GuardProgress, VirtualCallback};
    use amaterasu_module_sdk::extension_api::ProviderRequest;
    struct AllowGuard;
    impl EffectGuard for AllowGuard {
        fn poll(
            &mut self,
            _: &ProviderRequest,
            _: EffectKind,
            _: u64,
            _: u64,
            _: &mut impl FnMut(Command) -> ModuleResult<Response>,
        ) -> GuardProgress {
            GuardProgress::Authorized
        }
    }
    fn request(sequence: u64) -> ProviderRequest {
        let id = "9c1d707f-7229-4fc4-b6e2-91f80c626a09";
        let domain = "provider_session:abcdef";
        serde_json::from_value(json!({"provider_sequence":sequence,"operation":"lifecycle_callback","version":1,"transition_id":format!("transition-{sequence}"),"operation_id":format!("virtual-{sequence}"),"target":{"kind":"stream","host_epoch":"epoch-a","session_id":"session-1","stream_id":"stream-1","generation":7},"phase":"stream.prepare","settings_revision":"settings-1","settings":{},"intent":"initial","reason":null,"requested_video":null,"consumer_requirements":{"execution_domain":"desktop","capture_providers":["amaterasu.capture-pipewire/1"],"selector_schemas":["amaterasu.kwin-wl-output/1"]},"remaining_ms":5000,"plan_revision":1,"admission_id":"admission-1","approved_plan":{"plan_id":"plan-1","revision":1,"resources":[{"provider":crate::descriptor::PROVIDER,"resource_id":id,"incarnation":null,"expected_revision":null,"execution_domain":"desktop","mutation_domains":[domain],"access":"exclusive"}],"mutation_domains":[{"domain":domain,"expected_revision":1,"borrowers":{},"access":"exclusive"}],"required_capabilities":[],"constraints":{"virtual_display":{"provider_service":crate::virtual_display::SERVICE,"identity":id,"reference_id":"stream-1","width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false,"scale":null,"layout":"extended","domain_id":domain,"domain_revision":1,"geometry_revision":3,"borrow":null,"reference_released":false}},"obligations":[{"obligation_id":"cleanup-1","provider":crate::descriptor::PROVIDER,"resource_id":id,"mutation_domain":domain,"depends_on":[],"cleanup_method":{"service":crate::descriptor::SERVICE,"method":"lifecycle_callback","interface_major":1,"interface_minor":0,"schema_revision":1},"payload":{"service":crate::virtual_display::SERVICE,"identity":id,"reference_id":"stream-1"}}],"affected_consumers":[],"consumer_change":"reconnect_required","candidate_constraint":{"capture_provider":"amaterasu.capture-pipewire/1","selector_schema":"amaterasu.kwin-wl-output/1","resource_provider":crate::descriptor::PROVIDER,"resource_id":id,"incarnation":null,"execution_domain":"desktop","mode":{"width":1920,"height":1080,"refresh_millihz":60000,"hdr":false},"plan_revision":1},"allowed_degradation":[]}})).unwrap()
    }
    #[test]
    fn callback_receipt_window_rolls_over_without_erasing_obligations() {
        let mut state = super::tests::FakeState::default();
        for sequence in 1..=70 {
            let epoch = VerifiedEpoch::authenticate("epoch-a".into(), |_| true).unwrap();
            let target = VerifiedTarget::authenticate("session-1".into(), |_| true).unwrap();
            let mut store = VirtualDurableStateStore::new(
                epoch,
                target,
                format!("callback-{sequence}"),
                None,
                5000,
            )
            .unwrap();
            let mut callback = VirtualCallback::new(
                "amaterasu.session-lifecycle",
                request(sequence),
                None,
                |_| true,
                0,
                Some(99),
            )
            .unwrap();
            let mut guard = AllowGuard;
            let mut completed = false;
            for tick in 0..200 {
                let mut send = |command: Command| match &command {
                    Command::Request { service, .. }
                        if service == crate::virtual_display::SERVICE =>
                    {
                        Ok(Response::Error {
                            code: "disabled".into(),
                            message: "test rejection".into(),
                        })
                    }
                    _ => state.send(command),
                };
                store.advance(tick, &mut send);
                match callback.poll(tick, &mut send, &mut store, &mut guard) {
                    virtual_callback::CallbackProgress::Waiting => {}
                    virtual_callback::CallbackProgress::Complete(
                        virtual_callback::CallbackResult::Rejected { .. },
                    ) => {
                        completed = true;
                        break;
                    }
                    other => panic!("callback {sequence}: {other:?}"),
                }
            }
            assert!(completed, "callback {sequence} did not complete");
        }
        let mut lookup = PriorReceiptLookup::new(
            "amaterasu.session-lifecycle",
            1,
            "virtual-1".into(),
            "retired-check".into(),
            None,
            1000,
            0,
        )
        .unwrap();
        let mut outcome = PriorReceiptProgress::Waiting;
        for tick in 0..10 {
            outcome = lookup.poll(tick, &mut |command| state.send(command));
            if outcome != PriorReceiptProgress::Waiting {
                break;
            }
        }
        assert_eq!(outcome, PriorReceiptProgress::Expired);
        let epoch = VerifiedEpoch::authenticate("epoch-a".into(), |_| true).unwrap();
        let target = VerifiedTarget::authenticate("session-1".into(), |_| true).unwrap();
        let mut load =
            VirtualDurableStateStore::new(epoch, target, "obligation-check".into(), None, 1000)
                .unwrap();
        load.start_load().unwrap();
        for tick in 0..3 {
            load.advance(tick, &mut |command| state.send(command));
        }
        assert!(
            matches!(load.poll_load(),LoadProgress::Found(obligation) if obligation.reference_released)
        );
    }
}
