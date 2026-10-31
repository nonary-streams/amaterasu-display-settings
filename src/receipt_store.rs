//! Durable, bounded operation receipts using only `amaterasu.state/1`.
//!
//! Every effectful operation must wait for `Begun` before dispatch. A previously
//! pending operation is always recovery-required, never permission to replay.
//! An unknown write may still be in flight: fence/reconcile its broker request
//! before treating an absent lookup as authority to start again. Namespace and
//! collection access are bound to the runtime-authenticated module identity.
use amaterasu_module_sdk::{Command, ModuleResult, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const SERVICE: &str = "amaterasu.state/1";
const COLLECTION: &str = "display-settings/operation-receipts-v1";
const MAX_RECEIPTS: u64 = 64;
const MAX_CONTENT_BYTES: usize = 4096;
const MAX_CAS_ATTEMPTS: u8 = 3;
const MAX_TRANSPORT_FAILURES: u8 = 3;

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

#[derive(Clone, Debug)]
pub enum Operation {
    Begin {
        operation_id: String,
        request: Value,
    },
    Complete {
        operation_id: String,
        request: Value,
        result: Value,
    },
    Lookup {
        operation_id: String,
    },
}
impl Operation {
    fn id(&self) -> &str {
        match self {
            Self::Begin { operation_id, .. }
            | Self::Complete { operation_id, .. }
            | Self::Lookup { operation_id } => operation_id,
        }
    }
    fn validate(&self) -> Result<(), &'static str> {
        if !valid_operation_id(self.id()) {
            return Err("invalid_operation_id");
        }
        match self {
            Self::Begin { request, .. } => validate_content(request),
            Self::Complete {
                request, result, ..
            } => {
                validate_content(request)?;
                validate_content(result)
            }
            Self::Lookup { .. } => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// Pending receipt durably committed. Only this outcome allows first dispatch.
    Begun,
    /// No receipt at this instant. Does not fence an earlier unknown write.
    NotFound,
    RecoveryRequired(Receipt),
    Completed(Receipt),
    Conflict,
    Capacity,
    Contended,
    ProviderError(String),
    /// Broker admission, mutation, result release, or response was uncertain.
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
    Write,
}
struct Exchange {
    command: Command,
    request_id: Option<u64>,
    result: Option<Value>,
    failures: u8,
    uncertain: bool,
}

/// Owns one bounded state operation. One poll issues at most one broker command.
pub struct PendingStoreOperation {
    operation: Operation,
    prefix: String,
    parent: Option<u64>,
    timeout_ms: u64,
    deadline_ms: u64,
    phase: Phase,
    attempts: u8,
    exchange: Exchange,
    write_receipt: Option<Receipt>,
    write_revision: Option<u64>,
    finished: Option<Outcome>,
}
impl PendingStoreOperation {
    pub fn new(
        operation: Operation,
        broker_prefix: String,
        parent: Option<u64>,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        operation.validate()?;
        if !valid_id(&broker_prefix, 100) || !(1..=30_000).contains(&timeout_ms) {
            return Err("invalid_broker_operation");
        }
        let mut this = Self {
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
            operation,
            prefix: broker_prefix,
            parent,
            timeout_ms,
            deadline_ms: now_ms.saturating_add(timeout_ms),
            phase: Phase::Read,
            attempts: 0,
            write_receipt: None,
            write_revision: None,
            finished: None,
        };
        this.start_read();
        Ok(this)
    }
    /// Broker request currently being reconciled, if admission was observed.
    pub fn request_id(&self) -> Option<u64> {
        self.exchange.request_id
    }
    fn start_read(&mut self) {
        let payload =
            json!({"action":"collection_get","collection":COLLECTION,"key":self.operation.id()});
        self.set_exchange(payload, "read");
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
        if now_ms >= self.deadline_ms || self.exchange.failures >= MAX_TRANSPORT_FAILURES {
            return self.done(Outcome::Unknown);
        }
        if let Some(id) = self.exchange.request_id {
            if self.exchange.result.is_some() {
                match send(Command::ReleaseResult { request: id }) {
                    Ok(Response::Ok) => {
                        let payload = self.exchange.result.take().expect("result present");
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
                if self.attempts >= MAX_CAS_ATTEMPTS {
                    return self.done(Outcome::Contended);
                }
                self.start_read();
                return Progress::Waiting;
            }
            return self.done(Outcome::ProviderError(code.to_owned()));
        }
        match self.phase {
            Phase::Read => self.consume_read(payload),
            Phase::Write => {
                if payload.get("revision").and_then(Value::as_u64) != self.write_revision {
                    return self.done(Outcome::Unknown);
                }
                match self.write_receipt.take().expect("write receipt").state {
                    ReceiptState::Pending => self.done(Outcome::Begun),
                    ReceiptState::Completed { .. } => {
                        self.done(Outcome::Completed(self.completed_receipt()))
                    }
                }
            }
        }
    }
    fn completed_receipt(&self) -> Receipt {
        match &self.operation {
            Operation::Complete {
                operation_id,
                request,
                result,
            } => Receipt {
                operation_id: operation_id.clone(),
                request: request.clone(),
                state: ReceiptState::Completed {
                    result: result.clone(),
                },
            },
            _ => unreachable!("completion requires complete operation"),
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
        let metadata = &payload["metadata"];
        if found != (revision != 0)
            || (found && metadata != &json!({"format_version":1}))
            || (!found && (!metadata.is_null() || revision != 0 || count != 0))
            || count > MAX_RECEIPTS
        {
            return self.done(Outcome::Unknown);
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
            if receipt.operation_id != self.operation.id()
                || validate_content(&receipt.request).is_err()
                || matches!(&receipt.state, ReceiptState::Completed { result } if validate_content(result).is_err())
            {
                return self.done(Outcome::Unknown);
            }
            Some(receipt)
        };
        if !found && existing.is_some() || (count == 0 && existing.is_some()) {
            return self.done(Outcome::Unknown);
        }
        let receipt = match (&self.operation, existing) {
            (Operation::Lookup { .. }, None) => return self.done(Outcome::NotFound),
            (Operation::Lookup { .. }, Some(r)) => return self.done(receipt_outcome(r)),
            (
                Operation::Begin {
                    operation_id,
                    request,
                },
                None,
            ) => {
                if count >= MAX_RECEIPTS {
                    return self.done(Outcome::Capacity);
                }
                Receipt {
                    operation_id: operation_id.clone(),
                    request: request.clone(),
                    state: ReceiptState::Pending,
                }
            }
            (Operation::Begin { request, .. }, Some(r)) => {
                return if r.request != *request {
                    self.done(Outcome::Conflict)
                } else {
                    self.done(receipt_outcome(r))
                };
            }
            (Operation::Complete { .. }, None) => return self.done(Outcome::NotFound),
            (
                Operation::Complete {
                    request, result, ..
                },
                Some(r),
            ) => {
                if r.request != *request {
                    return self.done(Outcome::Conflict);
                }
                if let ReceiptState::Completed { result: previous } = &r.state {
                    return if previous == result {
                        self.done(Outcome::Completed(r))
                    } else {
                        self.done(Outcome::Conflict)
                    };
                }
                self.completed_receipt()
            }
        };
        let value = serde_json::to_value(&receipt).expect("receipt serializes");
        let body = json!({"action":"collection_commit","collection":COLLECTION,"expected_revision":revision,"metadata":{"format_version":1},"edits":[{"key":self.operation.id(),"value":value}]});
        let Some(next_revision) = revision.checked_add(1) else {
            return self.done(Outcome::Unknown);
        };
        self.write_revision = Some(next_revision);
        self.write_receipt = Some(receipt);
        self.set_exchange(body, "write");
        self.phase = Phase::Write;
        Progress::Waiting
    }
    fn done(&mut self, result: Outcome) -> Progress {
        self.finished = Some(result.clone());
        Progress::Done(result)
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
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'-' | b'/' | b':')
        })
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
    use std::collections::VecDeque;

    fn begin() -> Operation {
        Operation::Begin {
            operation_id: "operation.1".into(),
            request: json!({"mode":"1920x1080"}),
        }
    }
    fn entry(state: ReceiptState) -> Value {
        serde_json::to_value(Receipt {
            operation_id: "operation.1".into(),
            request: json!({"mode":"1920x1080"}),
            state,
        })
        .unwrap()
    }
    fn read(revision: u64, value: Value) -> Value {
        json!({"ok":true,"revision":revision,"found":revision != 0,"metadata":if revision == 0 { Value::Null } else { json!({"format_version":1}) },"count":if value.is_null() { 0 } else { 1 },"value":value})
    }
    fn sequence(payloads: Vec<Value>) -> VecDeque<ModuleResult<Response>> {
        let mut all = VecDeque::new();
        for (index, payload) in payloads.into_iter().enumerate() {
            all.push_back(Ok(Response::Accepted {
                id: index as u64 + 1,
            }));
            all.push_back(Ok(Response::Result { payload }));
            all.push_back(Ok(Response::Ok));
        }
        all
    }
    fn run(operation: Operation, payloads: Vec<Value>) -> (Outcome, Vec<Command>) {
        let mut call =
            PendingStoreOperation::new(operation, "receipt.test".into(), Some(99), 30000, 0)
                .unwrap();
        let mut replies = sequence(payloads);
        let mut commands = Vec::new();
        for tick in 0..50 {
            let progress = call.poll(tick, &mut |command| {
                commands.push(command);
                replies.pop_front().expect("unexpected request")
            });
            if let Progress::Done(outcome) = progress {
                return (outcome, commands);
            }
        }
        panic!("did not complete");
    }

    #[test]
    fn begin_requires_confirmed_cas_and_uses_collection_revision() {
        let (outcome, commands) = run(
            begin(),
            vec![read(0, Value::Null), json!({"ok":true,"revision":1})],
        );
        assert_eq!(outcome, Outcome::Begun);
        match &commands[3] {
            Command::Request {
                service,
                payload,
                parent,
                ..
            } => {
                assert_eq!(service, SERVICE);
                assert_eq!(*parent, Some(99));
                assert_eq!(payload["action"], "collection_commit");
                assert_eq!(payload["expected_revision"], 0);
                assert_eq!(payload["edits"][0]["value"]["state"]["state"], "pending");
            }
            _ => panic!("expected commit"),
        }
    }
    #[test]
    fn pending_after_restart_never_authorizes_reexecution_and_changed_payload_conflicts() {
        let (outcome, commands) = run(begin(), vec![read(1, entry(ReceiptState::Pending))]);
        assert!(matches!(outcome, Outcome::RecoveryRequired(_)));
        assert_eq!(commands.len(), 3);
        let changed = Operation::Begin {
            operation_id: "operation.1".into(),
            request: json!({"different":true}),
        };
        assert_eq!(
            run(changed, vec![read(1, entry(ReceiptState::Pending))]).0,
            Outcome::Conflict
        );
    }
    #[test]
    fn completion_and_duplicate_completion_use_immutable_result() {
        let op = || Operation::Complete {
            operation_id: "operation.1".into(),
            request: json!({"mode":"1920x1080"}),
            result: json!({"ok":true}),
        };
        let (outcome, commands) = run(
            op(),
            vec![
                read(3, entry(ReceiptState::Pending)),
                json!({"ok":true,"revision":4}),
            ],
        );
        assert!(matches!(outcome, Outcome::Completed(_)));
        assert!(
            matches!(&commands[3], Command::Request { payload, .. } if payload["expected_revision"] == 3)
        );
        let completed = entry(ReceiptState::Completed {
            result: json!({"ok":true}),
        });
        assert!(matches!(
            run(op(), vec![read(4, completed.clone())]).0,
            Outcome::Completed(_)
        ));
        let different = Operation::Complete {
            operation_id: "operation.1".into(),
            request: json!({"mode":"1920x1080"}),
            result: json!({"ok":false}),
        };
        assert_eq!(
            run(different, vec![read(4, completed)]).0,
            Outcome::Conflict
        );
    }
    #[test]
    fn cas_contention_rereads_and_discovers_existing_receipt() {
        let conflict =
            json!({"ok":false,"error":{"code":"revision_conflict","current_revision":1}});
        let (outcome, commands) = run(
            begin(),
            vec![
                read(0, Value::Null),
                conflict,
                read(1, entry(ReceiptState::Pending)),
            ],
        );
        assert!(matches!(outcome, Outcome::RecoveryRequired(_)));
        assert!(
            matches!(&commands[6], Command::Request { operation_id, .. } if operation_id == "receipt.test.read.1")
        );
    }
    #[test]
    fn full_store_and_unknown_commit_are_not_success() {
        let full = json!({"ok":true,"revision":5,"found":true,"metadata":{"format_version":1},"count":64,"value":null});
        assert_eq!(run(begin(), vec![full]).0, Outcome::Capacity);
        let mut call =
            PendingStoreOperation::new(begin(), "receipt.uncertain".into(), None, 10, 0).unwrap();
        let mut replies = sequence(vec![read(0, Value::Null)]);
        for tick in 0..3 {
            assert_eq!(
                call.poll(tick, &mut |_| replies.pop_front().unwrap()),
                Progress::Waiting
            );
        }
        assert_eq!(
            call.poll(3, &mut |_| Ok(Response::Accepted { id: 41 })),
            Progress::Waiting
        );
        assert_eq!(
            call.poll(10, &mut |_| unreachable!()),
            Progress::Done(Outcome::Unknown)
        );
        assert_eq!(call.request_id(), Some(41));
    }
    #[test]
    fn invalid_metadata_and_oversized_values_are_rejected() {
        let bad = json!({"ok":true,"revision":1,"found":true,"metadata":{"format_version":2},"count":0,"value":null});
        assert_eq!(run(begin(), vec![bad]).0, Outcome::Unknown);
        let oversized = Operation::Begin {
            operation_id: "id".into(),
            request: json!("x".repeat(5000)),
        };
        assert!(PendingStoreOperation::new(oversized, "prefix".into(), None, 1000, 0).is_err());
    }
}
