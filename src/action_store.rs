//! Bounded, durable action receipts scoped to an authenticated dispatcher epoch.
use crate::action_provider::{
    self, ActionOutcome, ActionStore, ExecuteRequest, StatusRequest, StoreCommand, StoreProgress,
};
use crate::receipt_store::{
    Operation, Outcome, PendingStoreOperation, Progress, Receipt, ReceiptState, VerifiedEpoch,
};
use amaterasu_module_sdk::extension_api::ActionTarget;
use amaterasu_module_sdk::{Command, ModuleResult, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format_version: u8,
    operation_id: String,
    request_digest: String,
    action_id: String,
    target: ActionTarget,
    plan_digest: String,
    outcome: Option<ActionOutcome>,
}
struct Pending {
    command: StoreCommand,
    operation: PendingStoreOperation,
    admission: Option<EpochAdmission>,
}
pub struct DurableActionStore {
    prefix: String,
    parent: Option<u64>,
    timeout_ms: u64,
    now_ms: u64,
    serial: u64,
    active: Option<Pending>,
    ready: Option<(StoreCommand, StoreProgress)>,
    poisoned: bool,
}
impl DurableActionStore {
    /// The supplied identity is the broker-authenticated caller, never payload data.
    pub fn new(
        caller: &str,
        prefix: String,
        parent: Option<u64>,
        timeout_ms: u64,
        verify_caller: impl FnOnce(&str) -> bool,
    ) -> Result<Self, &'static str> {
        if caller != action_provider::ACTION_CALLER
            || !verify_caller(caller)
            || !valid_prefix(&prefix)
            || !(1..=30_000).contains(&timeout_ms)
        {
            return Err("unauthorized_or_invalid_store");
        }
        Ok(Self {
            prefix,
            parent,
            timeout_ms,
            now_ms: 0,
            serial: 0,
            active: None,
            ready: None,
            poisoned: false,
        })
    }
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
        let Some(mut pending) = self.active.take() else {
            return;
        };
        if let Some(admission) = &mut pending.admission {
            match admission.poll(now_ms, send) {
                None => {
                    self.active = Some(pending);
                    return;
                }
                Some(false) => {
                    self.ready = Some((pending.command, StoreProgress::Unknown));
                    return;
                }
                Some(true) => pending.admission = None,
            }
        }
        match pending.operation.poll(now_ms, send) {
            Progress::Waiting => self.active = Some(pending),
            Progress::Done(outcome) => {
                let result = map_outcome(&pending.command, outcome);
                self.ready = Some((pending.command, result));
            }
        }
    }
}
impl ActionStore for DurableActionStore {
    fn poll(&mut self, command: &StoreCommand) -> StoreProgress {
        if self.poisoned {
            return StoreProgress::Unknown;
        }
        if let Some((prior, result)) = self.ready.take() {
            if prior != *command {
                self.poisoned = true;
                return StoreProgress::Unknown;
            }
            if result == StoreProgress::Unknown {
                self.poisoned = true;
            }
            return result;
        }
        if let Some(active) = &self.active {
            if active.command != *command {
                self.poisoned = true;
                return StoreProgress::Unknown;
            }
            return StoreProgress::Waiting;
        }
        let Some(serial) = self.serial.checked_add(1) else {
            self.poisoned = true;
            return StoreProgress::Unknown;
        };
        self.serial = serial;
        let Some((epoch, operation)) = operation(command) else {
            self.poisoned = true;
            return StoreProgress::Unknown;
        };
        match PendingStoreOperation::new_action_epoch(
            operation,
            &epoch,
            format!("{}.{}", self.prefix, serial),
            self.parent,
            self.timeout_ms,
            self.now_ms,
        ) {
            Ok(operation) => {
                self.active = Some(Pending {
                    command: command.clone(),
                    operation,
                    admission: Some(EpochAdmission::new(
                        &epoch,
                        command,
                        format!("{}.{}.admit", self.prefix, serial),
                        self.parent,
                        self.timeout_ms,
                        self.now_ms,
                    )),
                });
                StoreProgress::Waiting
            }
            Err(_) => {
                self.poisoned = true;
                StoreProgress::Unknown
            }
        }
    }
}
// Epoch tombstones are never evicted. Namespace exhaustion rejects new epochs.
struct EpochAdmission {
    epoch: String,
    prefix: String,
    parent: Option<u64>,
    timeout: u64,
    deadline: u64,
    phase: u8,
    attempt: u8,
    command: Command,
    id: Option<u64>,
    result: Option<Value>,
    expected_revision: Option<u64>,
}
impl EpochAdmission {
    fn new(
        epoch: &str,
        command: &StoreCommand,
        prefix: String,
        parent: Option<u64>,
        timeout: u64,
        now: u64,
    ) -> Self {
        let id = match command {
            StoreCommand::Begin { operation_id, .. }
            | StoreCommand::Complete { operation_id, .. } => operation_id,
            StoreCommand::Lookup { request } => &request.operation_id,
        };
        let key = format!("action-receipt/v1/{:x}", Sha256::digest(id.as_bytes()));
        let mut this = Self {
            epoch: epoch.into(),
            prefix,
            parent,
            timeout,
            deadline: now.saturating_add(timeout),
            phase: 0,
            attempt: 0,
            command: Command::ReleaseResult { request: 0 },
            id: None,
            result: None,
            expected_revision: None,
        };
        this.issue(json!({"action":"get","key":key}));
        this
    }
    fn issue(&mut self, payload: Value) {
        self.command = Command::Request {
            service: "amaterasu.state/1".into(),
            payload,
            timeout_ms: self.timeout,
            operation_id: format!("{}.{}.{}", self.prefix, self.phase, self.attempt),
            parent: self.parent,
        };
        self.id = None;
        self.result = None;
    }
    fn read_registry(&mut self) {
        self.phase = 1;
        self.issue(json!({"action":"collection_get","collection":"display-settings/action-epochs-v1","key":self.epoch}));
    }
    fn poll(
        &mut self,
        now: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> Option<bool> {
        if now >= self.deadline || self.attempt >= 3 {
            return Some(false);
        }
        if let Some(id) = self.id {
            if self.result.is_none() {
                match send(Command::TakeResult { request: id }) {
                    Ok(Response::Pending) => {}
                    Ok(Response::Result { payload }) => self.result = Some(payload),
                    _ => return Some(false),
                }
                return None;
            }
            if !matches!(
                send(Command::ReleaseResult { request: id }),
                Ok(Response::Ok)
            ) {
                return Some(false);
            }
            let result = self.result.take()?;
            if result.get("ok") != Some(&json!(true)) {
                if self.phase == 2
                    && result.pointer("/error/code") == Some(&json!("revision_conflict"))
                {
                    self.attempt += 1;
                    self.read_registry();
                    return None;
                }
                return Some(false);
            }
            match self.phase {
                0 => {
                    if result.get("found") != Some(&json!(false)) {
                        return Some(false);
                    }
                    self.read_registry();
                }
                1 => {
                    let rev = result.get("revision")?.as_u64()?;
                    let found = result.get("found")?.as_bool()?;
                    let count = result.get("count")?.as_u64()?;
                    if count > 128
                        || (found
                            && result.pointer("/metadata/count").and_then(Value::as_u64)
                                != Some(count))
                        || (!found && (rev != 0 || count != 0))
                    {
                        return Some(false);
                    }
                    if result.get("value") == Some(&json!(true)) {
                        return Some(true);
                    }
                    if !result.get("value")?.is_null() || count == 128 {
                        return Some(false);
                    }
                    self.expected_revision = rev.checked_add(1);
                    if self.expected_revision.is_none() {
                        return Some(false);
                    }
                    self.phase = 2;
                    self.issue(json!({"action":"collection_commit","collection":"display-settings/action-epochs-v1","expected_revision":rev,"metadata":{"count":count+1},"edits":[{"key":self.epoch,"value":true}]}));
                }
                2 => {
                    return Some(
                        result.get("revision").and_then(Value::as_u64) == self.expected_revision,
                    );
                }
                _ => return Some(false),
            }
            None
        } else {
            match send(self.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.id = Some(id);
                    None
                }
                _ => Some(false),
            }
        }
    }
}
fn operation(command: &StoreCommand) -> Option<(String, Operation)> {
    let id = match command {
        StoreCommand::Begin { operation_id, .. } | StoreCommand::Complete { operation_id, .. } => {
            operation_id
        }
        StoreCommand::Lookup { request } => &request.operation_id,
    };
    let (epoch, number) = id.split_once(':')?;
    if epoch.len() != 32
        || !epoch
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let sequence: u64 = number.parse().ok()?;
    if sequence == 0 || sequence.to_string() != number {
        return None;
    }
    // Caller authentication occurs at construction; the selected dispatcher owns its operation IDs.
    let token = VerifiedEpoch::authenticate(epoch.into(), |_| true).ok()?;
    let operation = match command {
        StoreCommand::Begin {
            operation_id,
            request,
        } => Operation::Begin {
            epoch: token,
            sequence,
            operation_id: operation_id.clone(),
            request: serde_json::to_value(record(operation_id, request)?).ok()?,
        },
        StoreCommand::Complete {
            operation_id,
            request,
            outcome,
        } => {
            if matches!(
                outcome,
                ActionOutcome::RecoveryRequired { .. }
                    | ActionOutcome::Failed {
                        cleanup_complete: false,
                        ..
                    }
            ) {
                return None;
            }
            Operation::Complete {
                epoch: token,
                sequence,
                operation_id: operation_id.clone(),
                request: serde_json::to_value(record(operation_id, request)?).ok()?,
                result: serde_json::to_value(outcome).ok()?,
            }
        }
        StoreCommand::Lookup { .. } => Operation::Lookup {
            epoch: token,
            sequence,
        },
    };
    Some((epoch.into(), operation))
}
fn decoded(receipt: Receipt) -> Option<Record> {
    let mut record: Record = serde_json::from_value(receipt.request).ok()?;
    if record.operation_id != receipt.operation_id
        || !valid_record(&record)
        || record.outcome.is_some()
    {
        return None;
    }
    record.outcome = match receipt.state {
        ReceiptState::Pending => None,
        ReceiptState::Completed { result } => Some(serde_json::from_value(result).ok()?),
    };
    Some(record)
}
fn map_outcome(command: &StoreCommand, outcome: Outcome) -> StoreProgress {
    match (command, outcome) {
        (StoreCommand::Begin { .. }, Outcome::Begun) => StoreProgress::Begun,
        (StoreCommand::Complete { .. }, Outcome::Completed(_)) => StoreProgress::Completed,
        (StoreCommand::Begin { .. }, Outcome::RecoveryRequired(receipt)) => {
            if decoded(receipt).is_some() {
                StoreProgress::ExistingPending
            } else {
                StoreProgress::Unknown
            }
        }
        (StoreCommand::Begin { .. }, Outcome::Completed(receipt)) => decoded(receipt)
            .and_then(|r| r.outcome)
            .map_or(StoreProgress::Unknown, StoreProgress::ExistingComplete),
        (
            StoreCommand::Lookup { request },
            Outcome::RecoveryRequired(receipt) | Outcome::Completed(receipt),
        ) => decoded(receipt).map_or(StoreProgress::Unknown, |r| lookup(request, r)),
        (StoreCommand::Lookup { .. }, Outcome::NotFound) => StoreProgress::NotFound,
        _ => StoreProgress::Unknown,
    }
}
fn record(operation_id: &str, request: &Value) -> Option<Record> {
    if serde_json::to_vec(request).ok()?.len() > 12 * 1024 {
        return None;
    }
    let parsed: ExecuteRequest = serde_json::from_value(request.clone()).ok()?;
    if parsed.operation_id != operation_id
        || !valid_id(operation_id)
        || parsed.version != 1
        || matches!(parsed.target, ActionTarget::Host { .. })
        || crate::actions::parse_action(&parsed.action_id, parsed.arguments.clone()).is_err()
        || parsed.plan.constraints.get("action")
            != Some(
                &json!({"operation_id":parsed.operation_id,"action_id":parsed.action_id,"target":parsed.target,"arguments":parsed.arguments,"expected_settings_revision":parsed.expected_settings_revision}),
            )
        || !valid_digest(&parsed.plan_digest)
        || action_provider::plan_digest(&parsed.plan).ok()? != parsed.plan_digest
    {
        return None;
    }
    Some(Record {
        format_version: 1,
        operation_id: operation_id.into(),
        request_digest: format!("{:x}", Sha256::digest(serde_json::to_vec(request).ok()?)),
        action_id: parsed.action_id,
        target: parsed.target,
        plan_digest: parsed.plan_digest,
        outcome: None,
    })
}
fn valid_record(record: &Record) -> bool {
    record.format_version == 1
        && valid_id(&record.operation_id)
        && valid_digest(&record.request_digest)
        && valid_digest(&record.plan_digest)
        && !record.action_id.is_empty()
        && record.action_id.len() <= 128
        && record
            .outcome
            .as_ref()
            .is_none_or(|value| serde_json::to_vec(value).is_ok_and(|v| v.len() <= 4096))
}
fn lookup(request: &StatusRequest, record: Record) -> StoreProgress {
    if request.version != 1
        || request.operation_id != record.operation_id
        || request.action_id != record.action_id
        || request.target != record.target
        || request.plan_digest != record.plan_digest
    {
        return StoreProgress::Unknown;
    }
    match record.outcome {
        None => StoreProgress::ExistingPending,
        Some(outcome) => {
            let receipt = match &outcome {
                ActionOutcome::Succeeded { receipt }
                | ActionOutcome::Failed { receipt, .. }
                | ActionOutcome::RecoveryRequired { receipt } => receipt,
            };
            if receipt == &request.provider_receipt {
                StoreProgress::ExistingComplete(outcome)
            } else {
                StoreProgress::Unknown
            }
        }
    }
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
fn valid_prefix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'/')
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    fn request() -> ExecuteRequest {
        let target = json!({"kind":"stream","host_epoch":"epoch-a","session_id":"session-1","stream_id":"stream-1","expected_generation":1});
        let action = json!({"operation_id":"0123456789abcdef0123456789abcdef:1","action_id":crate::actions::REMOVE_OWNED,"target":target,"arguments":{},"expected_settings_revision":"rev-1"});
        let plan=serde_json::from_value(json!({"plan_id":"plan-1","revision":1,"resources":[],"mutation_domains":[],"required_capabilities":[],"constraints":{"action":action},"obligations":[],"affected_consumers":[],"consumer_change":"live","candidate_constraint":null,"allowed_degradation":[]})).unwrap();
        let plan_digest = action_provider::plan_digest(&plan).unwrap();
        ExecuteRequest {
            version: 1,
            operation_id: "0123456789abcdef0123456789abcdef:1".into(),
            action_id: crate::actions::REMOVE_OWNED.into(),
            target: serde_json::from_value(target).unwrap(),
            arguments: json!({}),
            expected_settings_revision: Some("rev-1".into()),
            plan,
            plan_digest,
            permit: "secret".into(),
        }
    }
    #[derive(Default)]
    struct Collection {
        rev: u64,
        metadata: Value,
        values: BTreeMap<String, Value>,
    }
    #[derive(Default)]
    struct Fake {
        collections: BTreeMap<String, Collection>,
        result: Option<Value>,
        id: u64,
        legacy: bool,
        registry_conflict: bool,
    }
    impl Fake {
        fn send(&mut self, command: Command) -> ModuleResult<Response> {
            match command {
                Command::Request { payload, .. } => {
                    if payload["action"] == "get" {
                        self.id += 1;
                        self.result = Some(json!({"ok":true,"found":self.legacy,"revision":0}));
                        return Ok(Response::Accepted { id: self.id });
                    }
                    if self.registry_conflict
                        && payload["collection"] == "display-settings/action-epochs-v1"
                        && payload["action"] == "collection_commit"
                    {
                        self.registry_conflict = false;
                        self.id += 1;
                        self.result =
                            Some(json!({"ok":false,"error":{"code":"revision_conflict"}}));
                        return Ok(Response::Accepted { id: self.id });
                    }
                    let c = self
                        .collections
                        .entry(payload["collection"].as_str().unwrap().into())
                        .or_default();
                    let reply = match payload["action"].as_str().unwrap() {
                        "collection_get" => {
                            json!({"ok":true,"revision":c.rev,"found":c.rev!=0,"metadata":c.metadata,"count":c.values.len(),"value":c.values.get(payload["key"].as_str().unwrap())})
                        }
                        "collection_commit"
                            if payload["expected_revision"].as_u64() == Some(c.rev) =>
                        {
                            for edit in payload["edits"].as_array().unwrap() {
                                let key = edit["key"].as_str().unwrap().to_owned();
                                if edit["value"].is_null() {
                                    c.values.remove(&key);
                                } else {
                                    c.values.insert(key, edit["value"].clone());
                                }
                            }
                            c.metadata = payload["metadata"].clone();
                            c.rev += 1;
                            json!({"ok":true,"revision":c.rev})
                        }
                        _ => json!({"ok":false,"error":{"code":"revision_conflict"}}),
                    };
                    self.id += 1;
                    self.result = Some(reply);
                    Ok(Response::Accepted { id: self.id })
                }
                Command::TakeResult { .. } => Ok(Response::Result {
                    payload: self.result.clone().unwrap(),
                }),
                Command::ReleaseResult { .. } => {
                    self.result = None;
                    Ok(Response::Ok)
                }
                _ => panic!("unexpected command"),
            }
        }
        fn run(&mut self, store: &mut DurableActionStore, command: StoreCommand) -> StoreProgress {
            for _ in 0..100 {
                let result = store.poll(&command);
                if result != StoreProgress::Waiting {
                    return result;
                }
                store.advance(store.now_ms + 1, &mut |c| self.send(c));
            }
            panic!("stuck")
        }
    }
    fn store(prefix: &str) -> DurableActionStore {
        DurableActionStore::new(
            action_provider::ACTION_CALLER,
            prefix.into(),
            None,
            1000,
            |_| true,
        )
        .unwrap()
    }
    #[test]
    fn durable_begin_complete_and_exact_status_survive_restart() {
        let req = request();
        let value = serde_json::to_value(&req).unwrap();
        let mut state = Fake::default();
        let mut store = store("first");
        let begin = StoreCommand::Begin {
            operation_id: req.operation_id.clone(),
            request: value.clone(),
        };
        assert_eq!(state.run(&mut store, begin.clone()), StoreProgress::Begun);
        let mut resumed = super::tests::store("resume");
        assert_eq!(
            state.run(&mut resumed, begin),
            StoreProgress::ExistingPending
        );
        let outcome = ActionOutcome::Succeeded {
            receipt: json!({"lease":"owned"}),
        };
        assert_eq!(
            state.run(
                &mut store,
                StoreCommand::Complete {
                    operation_id: req.operation_id.clone(),
                    request: value,
                    outcome: outcome.clone()
                }
            ),
            StoreProgress::Completed
        );
        let status = StatusRequest {
            version: 1,
            operation_id: req.operation_id.clone(),
            action_id: req.action_id.clone(),
            target: req.target.clone(),
            plan_digest: req.plan_digest.clone(),
            provider_receipt: json!({"lease":"owned"}),
        };
        let mut fresh = super::tests::store("fresh");
        assert_eq!(
            state.run(
                &mut fresh,
                StoreCommand::Lookup {
                    request: status.clone()
                }
            ),
            StoreProgress::ExistingComplete(outcome)
        );
        let mut bad = super::tests::store("bad");
        let mut status = status;
        status.provider_receipt = json!({"lease":"other"});
        assert_eq!(
            state.run(&mut bad, StoreCommand::Lookup { request: status }),
            StoreProgress::Unknown
        );
        assert!(
            state
                .collections
                .values()
                .flat_map(|c| c.values.values())
                .all(|r| !r.to_string().contains("secret"))
        );
    }
    #[test]
    fn changed_reuse_and_uncertain_persistence_never_authorize_effect() {
        let req = request();
        let value = serde_json::to_value(req).unwrap();
        let mut state = Fake::default();
        let mut first = store("first");
        assert_eq!(
            state.run(
                &mut first,
                StoreCommand::Begin {
                    operation_id: "0123456789abcdef0123456789abcdef:1".into(),
                    request: value.clone()
                }
            ),
            StoreProgress::Begun
        );
        let mut changed = value;
        changed["permit"] = json!("different");
        let mut second = store("second");
        assert_eq!(
            state.run(
                &mut second,
                StoreCommand::Begin {
                    operation_id: "0123456789abcdef0123456789abcdef:1".into(),
                    request: changed
                }
            ),
            StoreProgress::Unknown
        );
        assert!(DurableActionStore::new("foreign", "id".into(), None, 1000, |_| true).is_err());
    }
    #[test]
    fn sparse_terminal_receipts_retire_without_replaying_and_pending_blocks() {
        let mut state = Fake::default();
        let mut store = store("cycles");
        let mut first = None;
        for n in 0..70 {
            let mut req = request();
            req.operation_id = format!("0123456789abcdef0123456789abcdef:{}", n * 2 + 1);
            req.plan.constraints["action"]["operation_id"] = json!(req.operation_id);
            req.plan_digest = action_provider::plan_digest(&req.plan).unwrap();
            let value = serde_json::to_value(&req).unwrap();
            let begin = StoreCommand::Begin {
                operation_id: req.operation_id.clone(),
                request: value.clone(),
            };
            if n == 0 {
                first = Some(begin.clone());
            }
            assert_eq!(state.run(&mut store, begin), StoreProgress::Begun);
            assert_eq!(
                state.run(
                    &mut store,
                    StoreCommand::Complete {
                        operation_id: req.operation_id,
                        request: value,
                        outcome: ActionOutcome::Succeeded {
                            receipt: json!({"cycle":n})
                        }
                    }
                ),
                StoreProgress::Completed
            );
        }
        let mut retry = super::tests::store("expired");
        assert_eq!(
            state.run(&mut retry, first.unwrap()),
            StoreProgress::Unknown
        );
        let collection = &state.collections["display-settings/action-receipts-v1/0123456789abcdef0123456789abcdef"];
        assert_eq!(collection.values.len(), 64);
        assert!(collection.metadata["low"].as_u64().unwrap() > 0);
        let mut req = request();
        req.operation_id = "0123456789abcdef0123456789abcdef:143".into();
        req.plan.constraints["action"]["operation_id"] = json!(req.operation_id);
        req.plan_digest = action_provider::plan_digest(&req.plan).unwrap();
        let begin = StoreCommand::Begin {
            operation_id: req.operation_id.clone(),
            request: serde_json::to_value(&req).unwrap(),
        };
        assert_eq!(state.run(&mut store, begin), StoreProgress::Begun);
        req.operation_id = "0123456789abcdef0123456789abcdef:145".into();
        req.plan.constraints["action"]["operation_id"] = json!(req.operation_id);
        req.plan_digest = action_provider::plan_digest(&req.plan).unwrap();
        assert_eq!(
            state.run(
                &mut store,
                StoreCommand::Begin {
                    operation_id: req.operation_id.clone(),
                    request: serde_json::to_value(req).unwrap()
                }
            ),
            StoreProgress::Unknown
        );
    }
    #[test]
    fn epoch_capacity_fails_closed() {
        let mut state = Fake::default();
        let registry = state
            .collections
            .entry("display-settings/action-epochs-v1".into())
            .or_default();
        registry.rev = 1;
        registry.metadata = json!({"count":128});
        for n in 0..128 {
            registry.values.insert(format!("{n:032x}"), json!(true));
        }
        let req = request();
        let mut store = store("full");
        assert_eq!(
            state.run(
                &mut store,
                StoreCommand::Begin {
                    operation_id: req.operation_id.clone(),
                    request: serde_json::to_value(req).unwrap()
                }
            ),
            StoreProgress::Unknown
        );
        assert_eq!(state.collections.len(), 1);
    }
    #[test]
    fn epoch_cas_conflict_retries_and_legacy_record_fences() {
        let req = request();
        let command = StoreCommand::Begin {
            operation_id: req.operation_id.clone(),
            request: serde_json::to_value(req).unwrap(),
        };
        let mut state = Fake {
            registry_conflict: true,
            ..Default::default()
        };
        let mut store = store("cas");
        assert_eq!(state.run(&mut store, command.clone()), StoreProgress::Begun);
        let registry = &state.collections["display-settings/action-epochs-v1"];
        assert_eq!(registry.values.len(), 1);
        let mut old = Fake {
            legacy: true,
            ..Default::default()
        };
        let mut store = super::tests::store("old");
        assert_eq!(old.run(&mut store, command), StoreProgress::Unknown);
        assert!(old.collections.is_empty());
    }
}
