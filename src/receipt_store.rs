//! Durable, bounded provider receipts via `amaterasu.state/1`.
//!
//! Only a coordinator-authenticated epoch may be used. An operation marked
//! pending is never replayed; reconcile its native effects before completion.
//! Epoch rollover additionally requires the coordinator to fence old callbacks.
use amaterasu_module_sdk::{Command, ModuleResult, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const SERVICE: &str = "amaterasu.state/1";
const COLLECTION: &str = "display-settings/operation-receipts-v2";
const WINDOW: u64 = 64;
const MAX_CONTENT_BYTES: usize = 4096;
const MAX_FAILURES: u8 = 3;

/// Authentication must check the exact selected lifecycle broker identity and
/// current epoch with the coordinator. Payload fields alone are not authority.
#[derive(Clone, Debug)]
pub struct VerifiedEpoch(String);
impl VerifiedEpoch {
    pub fn authenticate(
        epoch: String,
        verify: impl FnOnce(&str) -> bool,
    ) -> Result<Self, &'static str> {
        if !valid_id(&epoch, 80) || !verify(&epoch) {
            return Err("epoch_not_authenticated");
        }
        Ok(Self(epoch))
    }
}
/// Authentication must additionally prove old callbacks have been fenced and
/// no new call using the old epoch can arrive. Pending receipts survive the
/// switch and block new work until they are reconciled.
pub struct RolloverAuthorization {
    old: String,
    new: VerifiedEpoch,
}
impl RolloverAuthorization {
    pub fn authenticate(
        old: String,
        new: VerifiedEpoch,
        verify_fence: impl FnOnce(&str, &str) -> bool,
    ) -> Result<Self, &'static str> {
        if !valid_id(&old, 80) || old == new.0 || !verify_fence(&old, &new.0) {
            return Err("rollover_not_authenticated");
        }
        Ok(Self { old, new })
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReceiptState {
    Pending,
    Completed { result: Value },
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: String,
    pub request: Value,
    pub state: ReceiptState,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    format_version: u8,
    epoch: String,
    low: u64,
    high: u64,
    pending: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sequences: Vec<u64>,
}
impl Metadata {
    fn empty(epoch: String) -> Self {
        Self {
            format_version: 3,
            epoch,
            low: 0,
            high: 0,
            pending: 0,
            sequences: Vec::new(),
        }
    }
    fn validate(&self, count: u64) -> bool {
        self.format_version == 3
            && valid_id(&self.epoch, 80)
            && self.low <= self.high
            && self.sequences.len() <= WINDOW as usize
            && self.pending <= 1
            && self.pending <= count
            && count == self.sequences.len() as u64
            && self
                .sequences
                .iter()
                .all(|sequence| *sequence > self.low && *sequence <= self.high)
            && self.sequences.windows(2).all(|pair| pair[0] < pair[1])
            && self.sequences.last().copied().unwrap_or(self.low) == self.high
    }
    fn normalize(&mut self) -> bool {
        if self.format_version == 2 {
            if !self.sequences.is_empty() || self.low > self.high || self.high - self.low > WINDOW {
                return false;
            }
            if self.low < self.high {
                self.sequences = (self.low + 1..=self.high).collect();
            }
            self.format_version = 3;
        }
        true
    }
}
/// Each `Complete` means the callback effect is settled and any remaining
/// cleanup obligations are durably recorded separately.
/// `Retire` permanently discards only the oldest completed receipt.
pub enum Operation {
    Begin {
        epoch: VerifiedEpoch,
        sequence: u64,
        operation_id: String,
        request: Value,
    },
    Complete {
        epoch: VerifiedEpoch,
        sequence: u64,
        operation_id: String,
        request: Value,
        result: Value,
    },
    Lookup {
        epoch: VerifiedEpoch,
        sequence: u64,
    },
    Retire {
        epoch: VerifiedEpoch,
        sequence: u64,
    },
    Rollover {
        authorization: RolloverAuthorization,
    },
}
impl Operation {
    fn epoch(&self) -> &str {
        match self {
            Self::Begin { epoch, .. }
            | Self::Complete { epoch, .. }
            | Self::Lookup { epoch, .. }
            | Self::Retire { epoch, .. } => &epoch.0,
            Self::Rollover { authorization } => &authorization.old,
        }
    }
    fn sequence(&self) -> Option<u64> {
        match self {
            Self::Begin { sequence, .. }
            | Self::Complete { sequence, .. }
            | Self::Lookup { sequence, .. }
            | Self::Retire { sequence, .. } => Some(*sequence),
            Self::Rollover { .. } => None,
        }
    }
    fn key(&self) -> String {
        self.sequence()
            .map_or_else(|| "metadata".into(), |s| format!("{:020}", s))
    }
    fn validate(&self) -> Result<(), &'static str> {
        if self.sequence() == Some(0) {
            return Err("invalid_sequence");
        }
        match self {
            Self::Begin {
                request,
                operation_id,
                ..
            } => {
                if !valid_operation_id(operation_id) {
                    return Err("invalid_operation_id");
                }
                validate_content(request)
            }
            Self::Complete {
                request,
                result,
                operation_id,
                ..
            } => {
                if !valid_operation_id(operation_id) {
                    return Err("invalid_operation_id");
                }
                validate_content(request)?;
                validate_content(result)
            }
            _ => Ok(()),
        }
    }
    fn receipt(&self, state: ReceiptState) -> Receipt {
        let (operation_id, request) = match self {
            Self::Begin {
                operation_id,
                request,
                ..
            }
            | Self::Complete {
                operation_id,
                request,
                ..
            } => (operation_id.clone(), request.clone()),
            _ => unreachable!(),
        };
        Receipt {
            operation_id,
            request,
            state,
        }
    }
}
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Begun,
    NotFound,
    Expired,
    RecoveryRequired(Receipt),
    Completed(Receipt),
    Retired,
    RolledOver,
    Conflict,
    Capacity,
    SequenceWindow,
    EpochMismatch,
    Contended,
    ProviderError(String),
    Unknown,
}
#[derive(Clone, Debug, PartialEq)]
pub enum Progress {
    Waiting,
    Done(Outcome),
}
#[derive(Clone, Copy)]
enum Phase {
    Read,
    ReadOldest,
    Write,
}
struct Exchange {
    command: Command,
    request_id: Option<u64>,
    result: Option<Value>,
    failures: u8,
    uncertain: bool,
}

/// One broker command per poll. Unknown writes require broker fencing and
/// reconciliation; absence alone cannot disprove an in-flight write.
pub struct PendingStoreOperation {
    operation: Operation,
    collection: String,
    prefix: String,
    parent: Option<u64>,
    timeout_ms: u64,
    deadline_ms: u64,
    phase: Phase,
    attempts: u8,
    exchange: Exchange,
    write_outcome: Option<Outcome>,
    write_revision: Option<u64>,
    retirement: Option<(Metadata, u64)>,
    finished: Option<Outcome>,
}
impl PendingStoreOperation {
    pub fn new(
        operation: Operation,
        prefix: String,
        parent: Option<u64>,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        Self::in_collection(
            operation,
            COLLECTION.to_owned(),
            prefix,
            parent,
            timeout_ms,
            now_ms,
        )
    }
    /// A distinct collection for a broker-authenticated action dispatcher epoch.
    pub(crate) fn new_action_epoch(
        operation: Operation,
        epoch: &str,
        prefix: String,
        parent: Option<u64>,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        if epoch.len() != 32
            || !epoch
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || operation.epoch() != epoch
            || matches!(operation, Operation::Rollover { .. })
        {
            return Err("invalid_action_epoch");
        }
        Self::in_collection(
            operation,
            format!("display-settings/action-receipts-v1/{epoch}"),
            prefix,
            parent,
            timeout_ms,
            now_ms,
        )
    }
    fn in_collection(
        operation: Operation,
        collection: String,
        prefix: String,
        parent: Option<u64>,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        operation.validate()?;
        if !valid_id(&prefix, 100) || !(1..=30_000).contains(&timeout_ms) {
            return Err("invalid_broker_operation");
        }
        let mut call = Self {
            operation,
            collection,
            prefix,
            parent,
            timeout_ms,
            deadline_ms: now_ms.saturating_add(timeout_ms),
            phase: Phase::Read,
            attempts: 0,
            exchange: Exchange {
                command: Command::Request {
                    service: SERVICE.into(),
                    payload: Value::Null,
                    timeout_ms,
                    operation_id: String::new(),
                    parent,
                },
                request_id: None,
                result: None,
                failures: 0,
                uncertain: false,
            },
            write_outcome: None,
            write_revision: None,
            retirement: None,
            finished: None,
        };
        call.start_read();
        Ok(call)
    }
    pub fn request_id(&self) -> Option<u64> {
        self.exchange.request_id
    }
    fn start_read(&mut self) {
        self.set_exchange(
            json!({"action":"collection_get","collection":self.collection,"key":self.operation.key()}),
            "read",
        );
        self.phase = Phase::Read;
    }
    fn set_exchange(&mut self, payload: Value, label: &str) {
        self.exchange = Exchange {
            command: Command::Request {
                service: SERVICE.into(),
                payload,
                timeout_ms: self.timeout_ms,
                operation_id: format!("{}.{}.{}", self.prefix, label, self.attempts),
                parent: self.parent,
            },
            request_id: None,
            result: None,
            failures: 0,
            uncertain: false,
        };
    }
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> Progress {
        if let Some(outcome) = &self.finished {
            return Progress::Done(outcome.clone());
        }
        if now_ms >= self.deadline_ms || self.exchange.failures >= MAX_FAILURES {
            return self.done(Outcome::Unknown);
        }
        if let Some(id) = self.exchange.request_id {
            if self.exchange.result.is_some() {
                match send(Command::ReleaseResult { request: id }) {
                    Ok(Response::Ok) => {
                        let payload = self.exchange.result.take().expect("result");
                        self.consume(payload)
                    }
                    _ => {
                        self.exchange.failures += 1;
                        Progress::Waiting
                    }
                }
            } else {
                match send(Command::TakeResult { request: id }) {
                    Ok(Response::Pending) => Progress::Waiting,
                    Ok(Response::Result { payload }) => {
                        self.exchange.result = Some(payload);
                        Progress::Waiting
                    }
                    _ => {
                        self.exchange.failures += 1;
                        Progress::Waiting
                    }
                }
            }
        } else {
            match send(self.exchange.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.exchange.request_id = Some(id);
                    self.exchange.failures = 0;
                    Progress::Waiting
                }
                Ok(Response::Error { code, .. }) if !self.exchange.uncertain => {
                    self.done(Outcome::ProviderError(code))
                }
                _ => {
                    self.exchange.uncertain = true;
                    self.exchange.failures += 1;
                    Progress::Waiting
                }
            }
        }
    }
    fn consume(&mut self, payload: Value) -> Progress {
        let Some(ok) = payload.get("ok").and_then(Value::as_bool) else {
            return self.done(Outcome::Unknown);
        };
        if !ok {
            let Some(code) = payload.pointer("/error/code").and_then(Value::as_str) else {
                return self.done(Outcome::Unknown);
            };
            if matches!(self.phase, Phase::Write) && code == "revision_conflict" {
                self.attempts += 1;
                if self.attempts >= MAX_FAILURES {
                    return self.done(Outcome::Contended);
                }
                self.start_read();
                return Progress::Waiting;
            }
            return self.done(Outcome::ProviderError(code.into()));
        }
        match self.phase {
            Phase::Read => self.consume_read(payload),
            Phase::ReadOldest => self.consume_oldest(payload),
            Phase::Write => {
                if payload.get("revision").and_then(Value::as_u64) != self.write_revision {
                    return self.done(Outcome::Unknown);
                }
                let result = self.write_outcome.take().expect("write outcome");
                self.done(result)
            }
        }
    }
    fn consume_read(&mut self, payload: Value) -> Progress {
        let Some(revision) = payload.get("revision").and_then(Value::as_u64) else {
            return self.done(Outcome::Unknown);
        };
        let Some(count) = payload.get("count").and_then(Value::as_u64) else {
            return self.done(Outcome::Unknown);
        };
        let Some(found) = payload.get("found").and_then(Value::as_bool) else {
            return self.done(Outcome::Unknown);
        };
        if found != (revision != 0) {
            return self.done(Outcome::Unknown);
        }
        let mut meta = if !found {
            if count != 0 || !payload["metadata"].is_null() {
                return self.done(Outcome::Unknown);
            }
            Metadata::empty(self.operation.epoch().to_owned())
        } else {
            let Ok(meta) = serde_json::from_value::<Metadata>(payload["metadata"].clone()) else {
                return self.done(Outcome::Unknown);
            };
            meta
        };
        if !meta.normalize() || !meta.validate(count) {
            return self.done(Outcome::Unknown);
        }
        if meta.epoch != self.operation.epoch() {
            return self.done(Outcome::EpochMismatch);
        }
        let Some(value) = payload.get("value") else {
            return self.done(Outcome::Unknown);
        };
        let existing: Option<Receipt> = if value.is_null() {
            None
        } else {
            let Ok(receipt) = serde_json::from_value::<Receipt>(value.clone()) else {
                return self.done(Outcome::Unknown);
            };
            if !valid_operation_id(&receipt.operation_id)
                || validate_content(&receipt.request).is_err()
                || matches!(&receipt.state, ReceiptState::Completed { result } if validate_content(result).is_err())
            {
                return self.done(Outcome::Unknown);
            }
            Some(receipt)
        };
        if let Some(sequence) = self.operation.sequence() {
            if sequence <= meta.low {
                return self.done(Outcome::Expired);
            }
            if sequence <= meta.high {
                let retained = meta.sequences.binary_search(&sequence).is_ok();
                match (retained, existing.is_some()) {
                    (false, false) => return self.done(Outcome::Expired),
                    (true, false) | (false, true) => return self.done(Outcome::Unknown),
                    (true, true) => {}
                }
            }
            if sequence > meta.high && existing.is_some() {
                return self.done(Outcome::Unknown);
            }
        }
        let mut edits = Vec::new();
        let outcome = match (&self.operation, existing) {
            (Operation::Lookup { .. }, None) => return self.done(Outcome::NotFound),
            (Operation::Lookup { .. }, Some(r)) => return self.done(receipt_outcome(r)),
            (Operation::Begin { sequence, .. }, None) => {
                if *sequence <= meta.high {
                    return self.done(Outcome::SequenceWindow);
                }
                if meta.pending != 0 {
                    return self.done(Outcome::SequenceWindow);
                }
                if count >= WINDOW {
                    let Some(&oldest) = meta.sequences.first() else {
                        return self.done(Outcome::Unknown);
                    };
                    self.retirement = Some((meta, revision));
                    self.set_exchange(json!({"action":"collection_get","collection":self.collection,"key":format!("{oldest:020}")}), "oldest");
                    self.phase = Phase::ReadOldest;
                    return Progress::Waiting;
                }
                meta.high = *sequence;
                meta.pending += 1;
                meta.sequences.push(*sequence);
                let receipt = self.operation.receipt(ReceiptState::Pending);
                edits.push(json!({"key":self.operation.key(),"value":receipt}));
                Outcome::Begun
            }
            (
                Operation::Begin {
                    request,
                    operation_id,
                    ..
                },
                Some(r),
            ) => {
                return if r.request != *request || r.operation_id != *operation_id {
                    self.done(Outcome::Conflict)
                } else {
                    self.done(receipt_outcome(r))
                };
            }
            (Operation::Complete { .. }, None) => return self.done(Outcome::NotFound),
            (
                Operation::Complete {
                    request,
                    result,
                    operation_id,
                    ..
                },
                Some(r),
            ) => {
                if r.request != *request || r.operation_id != *operation_id {
                    return self.done(Outcome::Conflict);
                }
                if let ReceiptState::Completed { result: previous } = &r.state {
                    return if previous == result {
                        self.done(Outcome::Completed(r))
                    } else {
                        self.done(Outcome::Conflict)
                    };
                }
                if meta.pending == 0 {
                    return self.done(Outcome::Unknown);
                }
                meta.pending -= 1;
                let receipt = self.operation.receipt(ReceiptState::Completed {
                    result: result.clone(),
                });
                edits.push(json!({"key":self.operation.key(),"value":receipt}));
                Outcome::Completed(receipt)
            }
            (Operation::Retire { sequence, .. }, Some(r)) => {
                if meta.sequences.first().copied() != Some(*sequence) {
                    return self.done(Outcome::SequenceWindow);
                }
                if matches!(r.state, ReceiptState::Pending) {
                    return self.done(Outcome::RecoveryRequired(r));
                }
                meta.low = *sequence;
                meta.sequences.remove(0);
                edits.push(json!({"key":self.operation.key(),"value":null}));
                Outcome::Retired
            }
            (Operation::Retire { .. }, None) => return self.done(Outcome::NotFound),
            (Operation::Rollover { authorization }, _) => {
                meta.epoch = authorization.new.0.clone();
                Outcome::RolledOver
            }
        };
        let Some(next) = revision.checked_add(1) else {
            return self.done(Outcome::Unknown);
        };
        self.write_revision = Some(next);
        self.write_outcome = Some(outcome);
        self.set_exchange(json!({"action":"collection_commit","collection":self.collection,"expected_revision":revision,"metadata":meta,"edits":edits}), "write");
        self.phase = Phase::Write;
        Progress::Waiting
    }
    fn done(&mut self, result: Outcome) -> Progress {
        self.finished = Some(result.clone());
        Progress::Done(result)
    }
    /// Read and validate the oldest result before deleting it in the same CAS
    /// that admits the new pending record. Separate recovery journals remain.
    fn consume_oldest(&mut self, payload: Value) -> Progress {
        let Some((mut metadata, revision)) = self.retirement.take() else {
            return self.done(Outcome::Unknown);
        };
        if payload.get("revision").and_then(Value::as_u64) != Some(revision) {
            self.attempts += 1;
            if self.attempts >= MAX_FAILURES {
                return self.done(Outcome::Contended);
            }
            self.start_read();
            return Progress::Waiting;
        }
        let observed = payload
            .get("metadata")
            .cloned()
            .and_then(|v| serde_json::from_value::<Metadata>(v).ok())
            .and_then(|mut v| v.normalize().then_some(v));
        if payload.get("found").and_then(Value::as_bool) != Some(true)
            || payload.get("count").and_then(Value::as_u64) != Some(WINDOW)
            || observed.as_ref() != Some(&metadata)
        {
            return self.done(Outcome::Unknown);
        }
        let Some(value) = payload.get("value") else {
            return self.done(Outcome::Unknown);
        };
        let Ok(oldest) = serde_json::from_value::<Receipt>(value.clone()) else {
            return self.done(Outcome::Unknown);
        };
        if !valid_operation_id(&oldest.operation_id)
            || validate_content(&oldest.request).is_err()
            || !matches!(&oldest.state, ReceiptState::Completed { result } if validate_content(result).is_ok())
        {
            return self.done(Outcome::Unknown);
        }
        let Some(sequence) = self.operation.sequence() else {
            return self.done(Outcome::Unknown);
        };
        if !matches!(self.operation, Operation::Begin { .. })
            || metadata.pending != 0
            || sequence <= metadata.high
        {
            return self.done(Outcome::Unknown);
        }
        let Some(&low) = metadata.sequences.first() else {
            return self.done(Outcome::Unknown);
        };
        let Some(next_revision) = revision.checked_add(1) else {
            return self.done(Outcome::Unknown);
        };
        metadata.low = low;
        metadata.sequences.remove(0);
        metadata.high = sequence;
        metadata.pending = 1;
        metadata.sequences.push(sequence);
        let receipt = self.operation.receipt(ReceiptState::Pending);
        self.write_revision = Some(next_revision);
        self.write_outcome = Some(Outcome::Begun);
        self.set_exchange(json!({"action":"collection_commit","collection":self.collection,"expected_revision":revision,"metadata":metadata,"edits":[{"key":format!("{low:020}"),"value":null},{"key":self.operation.key(),"value":receipt}]}), "write");
        self.phase = Phase::Write;
        Progress::Waiting
    }
}
fn receipt_outcome(receipt: Receipt) -> Outcome {
    match receipt.state {
        ReceiptState::Pending => Outcome::RecoveryRequired(receipt),
        ReceiptState::Completed { .. } => Outcome::Completed(receipt),
    }
}
fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'/')
        })
}
fn valid_operation_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_graphic())
}
fn validate_content(value: &Value) -> Result<(), &'static str> {
    if serde_json::to_vec(value).is_ok_and(|v| v.len() <= MAX_CONTENT_BYTES) {
        Ok(())
    } else {
        Err("content_too_large")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn epoch(name: &str) -> VerifiedEpoch {
        VerifiedEpoch::authenticate(name.into(), |_| true).unwrap()
    }
    fn begin(epoch: &str, sequence: u64) -> Operation {
        Operation::Begin {
            epoch: self::epoch(epoch),
            sequence,
            operation_id: format!("caller:{sequence}"),
            request: json!({"sequence":sequence}),
        }
    }
    fn complete(epoch: &str, sequence: u64) -> Operation {
        Operation::Complete {
            epoch: self::epoch(epoch),
            sequence,
            operation_id: format!("caller:{sequence}"),
            request: json!({"sequence":sequence}),
            result: json!({"settled":true}),
        }
    }
    fn lookup(epoch: &str, sequence: u64) -> Operation {
        Operation::Lookup {
            epoch: self::epoch(epoch),
            sequence,
        }
    }
    fn retire(epoch: &str, sequence: u64) -> Operation {
        Operation::Retire {
            epoch: self::epoch(epoch),
            sequence,
        }
    }
    #[derive(Default)]
    struct FakeState {
        revision: u64,
        metadata: Value,
        entries: BTreeMap<String, Value>,
        pending: Option<Value>,
        next_id: u64,
        cas_conflicts: usize,
    }
    impl FakeState {
        fn send(&mut self, command: Command) -> ModuleResult<Response> {
            match command {
                Command::Request { payload, .. } => {
                    let reply = match payload["action"].as_str().unwrap() {
                        "collection_get" => {
                            json!({"ok":true,"revision":self.revision,"found":self.revision != 0,"metadata":self.metadata,"count":self.entries.len(),"value":self.entries.get(payload["key"].as_str().unwrap())})
                        }
                        "collection_commit" => {
                            if self.cas_conflicts > 0 {
                                self.cas_conflicts -= 1;
                                json!({"ok":false,"error":{"code":"revision_conflict"}})
                            } else if payload["expected_revision"].as_u64() != Some(self.revision) {
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
                                self.revision += 1;
                                json!({"ok":true,"revision":self.revision})
                            }
                        }
                        _ => panic!("unknown state operation"),
                    };
                    self.pending = Some(reply);
                    self.next_id += 1;
                    Ok(Response::Accepted { id: self.next_id })
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
        fn run(&mut self, op: Operation) -> Outcome {
            let mut call =
                PendingStoreOperation::new(op, format!("fake.{}", self.revision), None, 30000, 0)
                    .unwrap();
            for tick in 0..50 {
                if let Progress::Done(outcome) = call.poll(tick, &mut |command| self.send(command))
                {
                    return outcome;
                }
            }
            panic!("operation did not complete")
        }
    }
    #[test]
    fn more_than_window_operations_can_retire_without_replay() {
        let mut state = FakeState::default();
        for sequence in 1..=100 {
            assert_eq!(state.run(begin("epoch-a", sequence)), Outcome::Begun);
            assert!(matches!(
                state.run(complete("epoch-a", sequence)),
                Outcome::Completed(_)
            ));
            assert_eq!(state.run(retire("epoch-a", sequence)), Outcome::Retired);
        }
        assert_eq!(state.run(begin("epoch-a", 1)), Outcome::Expired);
        assert_eq!(state.run(lookup("epoch-a", 100)), Outcome::Expired);
        assert_eq!(state.metadata["low"], 100);
        assert_eq!(state.metadata["high"], 100);
    }
    #[test]
    fn full_window_automatically_retires_only_completed_receipts() {
        let mut state = FakeState::default();
        for sequence in 1..=100 {
            assert_eq!(state.run(begin("epoch-a", sequence)), Outcome::Begun);
            assert!(matches!(
                state.run(complete("epoch-a", sequence)),
                Outcome::Completed(_)
            ));
        }
        assert_eq!(state.metadata["low"], 36);
        assert_eq!(state.metadata["high"], 100);
        assert_eq!(state.entries.len(), 64);
        assert_eq!(state.run(lookup("epoch-a", 36)), Outcome::Expired);
        assert!(matches!(
            state.run(lookup("epoch-a", 37)),
            Outcome::Completed(_)
        ));
        assert_eq!(state.run(begin("epoch-a", 1)), Outcome::Expired);
    }
    #[test]
    fn oldest_pending_or_unreadable_record_is_never_retired() {
        let mut state = FakeState::default();
        for sequence in 1..=64 {
            assert_eq!(state.run(begin("epoch-a", sequence)), Outcome::Begun);
            assert!(matches!(
                state.run(complete("epoch-a", sequence)),
                Outcome::Completed(_)
            ));
        }
        let key = format!("{:020}", 1);
        state.entries.get_mut(&key).unwrap()["state"] = json!({"state":"pending"});
        let prior_revision = state.revision;
        assert_eq!(state.run(begin("epoch-a", 65)), Outcome::Unknown);
        assert_eq!(state.revision, prior_revision);
        assert!(state.entries.contains_key(&key));
        assert!(!state.entries.contains_key(&format!("{:020}", 65)));
    }
    #[test]
    fn sparse_first_sequence_and_gaps_are_never_replayed() {
        let mut state = FakeState::default();
        assert_eq!(state.run(begin("epoch-a", 12)), Outcome::Begun);
        assert!(matches!(
            state.run(complete("epoch-a", 12)),
            Outcome::Completed(_)
        ));
        assert_eq!(state.run(begin("epoch-a", 17)), Outcome::Begun);
        assert_eq!(state.run(begin("epoch-a", 13)), Outcome::Expired);
        assert_eq!(state.run(lookup("epoch-a", 16)), Outcome::Expired);
        assert!(matches!(
            state.run(complete("epoch-a", 17)),
            Outcome::Completed(_)
        ));
        assert_eq!(state.run(retire("epoch-a", 12)), Outcome::Retired);
        assert_eq!(state.metadata["low"], 12);
        assert_eq!(state.run(lookup("epoch-a", 12)), Outcome::Expired);
        assert!(matches!(
            state.run(lookup("epoch-a", 17)),
            Outcome::Completed(_)
        ));
    }
    #[test]
    fn sparse_window_retirement_and_legacy_migration_keep_cas_invariants() {
        let mut state = FakeState::default();
        for sequence in (1..=127).step_by(2) {
            assert_eq!(state.run(begin("epoch-a", sequence)), Outcome::Begun);
            assert!(matches!(
                state.run(complete("epoch-a", sequence)),
                Outcome::Completed(_)
            ));
        }
        state.cas_conflicts = 1;
        assert_eq!(state.run(begin("epoch-a", 140)), Outcome::Begun);
        assert_eq!(state.metadata["low"], 1);
        assert_eq!(state.run(lookup("epoch-a", 2)), Outcome::Expired);
        assert!(matches!(
            state.run(lookup("epoch-a", 3)),
            Outcome::Completed(_)
        ));
        let mut legacy = FakeState::default();
        assert_eq!(legacy.run(begin("epoch-a", 1)), Outcome::Begun);
        assert!(matches!(
            legacy.run(complete("epoch-a", 1)),
            Outcome::Completed(_)
        ));
        legacy.metadata["format_version"] = json!(2);
        legacy.metadata.as_object_mut().unwrap().remove("sequences");
        assert_eq!(legacy.run(begin("epoch-a", 10)), Outcome::Begun);
        assert_eq!(legacy.metadata["format_version"], 3);
        assert_eq!(legacy.metadata["sequences"], json!([1, 10]));
    }
    #[test]
    fn pending_blocks_new_sequence_retirement_and_changed_retry() {
        let mut state = FakeState::default();
        assert_eq!(state.run(begin("epoch-a", 1)), Outcome::Begun);
        assert!(matches!(
            state.run(begin("epoch-a", 1)),
            Outcome::RecoveryRequired(_)
        ));
        assert_eq!(state.run(begin("epoch-a", 2)), Outcome::SequenceWindow);
        assert!(matches!(
            state.run(retire("epoch-a", 1)),
            Outcome::RecoveryRequired(_)
        ));
        let changed = Operation::Begin {
            epoch: epoch("epoch-a"),
            sequence: 1,
            operation_id: "other".into(),
            request: json!({"sequence":1}),
        };
        assert_eq!(state.run(changed), Outcome::Conflict);
        assert!(matches!(
            state.run(complete("epoch-a", 1)),
            Outcome::Completed(_)
        ));
        assert!(matches!(
            state.run(complete("epoch-a", 1)),
            Outcome::Completed(_)
        ));
    }
    #[test]
    fn authenticated_epoch_switch_keeps_sequence_and_pending_recovery() {
        let mut state = FakeState::default();
        assert_eq!(state.run(begin("epoch-a", 1)), Outcome::Begun);
        let auth =
            RolloverAuthorization::authenticate("epoch-a".into(), epoch("epoch-b"), |old, new| {
                old == "epoch-a" && new == "epoch-b"
            })
            .unwrap();
        assert_eq!(
            state.run(Operation::Rollover {
                authorization: auth
            }),
            Outcome::RolledOver
        );
        assert_eq!(state.run(begin("epoch-a", 2)), Outcome::EpochMismatch);
        assert_eq!(state.run(begin("epoch-b", 2)), Outcome::SequenceWindow);
        assert!(matches!(
            state.run(complete("epoch-b", 1)),
            Outcome::Completed(_)
        ));
        assert_eq!(state.run(retire("epoch-b", 1)), Outcome::Retired);
        assert_eq!(state.run(begin("epoch-b", 1)), Outcome::Expired);
        assert_eq!(state.run(begin("epoch-b", 2)), Outcome::Begun);
        assert!(VerifiedEpoch::authenticate("epoch-c".into(), |_| false).is_err());
        assert!(
            RolloverAuthorization::authenticate("epoch-b".into(), epoch("epoch-c"), |_, _| false)
                .is_err()
        );
    }
    #[test]
    fn cas_contention_and_uncertain_write_remain_explicit() {
        let mut state = FakeState {
            cas_conflicts: 3,
            ..Default::default()
        };
        assert_eq!(state.run(begin("epoch-a", 1)), Outcome::Contended);
        let mut call =
            PendingStoreOperation::new(begin("epoch-a", 1), "test".into(), None, 5, 0).unwrap();
        assert_eq!(call.poll(0, &mut |_| Err("lost".into())), Progress::Waiting);
        assert_eq!(
            call.poll(5, &mut |_| unreachable!()),
            Progress::Done(Outcome::Unknown)
        );
    }
}
