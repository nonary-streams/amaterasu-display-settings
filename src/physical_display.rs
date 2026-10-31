//! Broker adapter for `amaterasu.display/1` physical topology leases.
//!
//! The service owns the native recovery journal. The caller must also durably
//! persist the supplied obligation before dispatch and whenever it changes;
//! this adapter cannot make an in-memory callback durable. Restart recovery must
//! use the same authenticated broker identity and reconcile `status` first.
//! No response from this adapter establishes capture readiness.
use std::collections::BTreeSet;

use amaterasu_module_sdk::{Command, ModuleResult, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SERVICE: &str = "amaterasu.display/1";
const MAX_FAILURES: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rational {
    pub numerator: u32,
    pub denominator: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rotation {
    #[default]
    Identity,
    Rotate90,
    Rotate180,
    Rotate270,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplaySetting {
    pub id: String,
    pub width: u32,
    pub height: u32,
    pub refresh: Rational,
    pub x: i32,
    pub y: i32,
    #[serde(default)]
    pub rotation: Rotation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hdr_enabled: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub displays: Vec<DisplaySetting>,
}

impl Configuration {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.displays.is_empty() || self.displays.len() > 16 {
            return Err("invalid_configuration");
        }
        let mut ids = BTreeSet::new();
        let mut primary = false;
        for display in &self.displays {
            let rate = &display.refresh;
            if display.id.is_empty()
                || display.id.len() > 1024
                || display.id.chars().any(char::is_control)
                || !ids.insert(display.id.to_lowercase())
                || !(320..=16_384).contains(&display.width)
                || !(200..=16_384).contains(&display.height)
                || rate.numerator == 0
                || rate.numerator > 1_000_000
                || rate.denominator == 0
                || rate.denominator > 100_000
                || u64::from(rate.numerator) < u64::from(rate.denominator)
                || u64::from(rate.numerator) > u64::from(rate.denominator) * 1000
                || display.x.abs_diff(0) > 65_536
                || display.y.abs_diff(0) > 65_536
            {
                return Err("invalid_configuration");
            }
            primary |= display.x == 0 && display.y == 0;
        }
        if !primary {
            return Err("invalid_configuration");
        }
        for (i, left) in self.displays.iter().enumerate() {
            for right in self.displays.iter().skip(i + 1) {
                let overlap = i64::from(left.x) < i64::from(right.x) + i64::from(right.width)
                    && i64::from(right.x) < i64::from(left.x) + i64::from(left.width)
                    && i64::from(left.y) < i64::from(right.y) + i64::from(right.height)
                    && i64::from(right.y) < i64::from(left.y) + i64::from(left.height);
                if overlap
                    && (left.x != right.x
                        || left.y != right.y
                        || left.width != right.width
                        || left.height != right.height)
                {
                    return Err("invalid_configuration");
                }
            }
        }
        Ok(())
    }
}

/// Persist this record atomically with the session's recovery journal. An
/// absent lease means the apply may still have taken effect; query owner status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObligation {
    pub operation_id: String,
    pub configuration: Configuration,
    pub topology_revision: String,
    pub lease: Option<String>,
    pub restored: bool,
}

impl RecoveryObligation {
    pub fn new(
        operation_id: String,
        configuration: Configuration,
        topology_revision: String,
    ) -> Result<Self, &'static str> {
        if !valid_id(&operation_id) || !valid_revision(&topology_revision) {
            return Err("invalid_operation");
        }
        configuration.validate()?;
        Ok(Self {
            operation_id,
            configuration,
            topology_revision,
            lease: None,
            restored: false,
        })
    }
    fn validate(&self) -> Result<(), &'static str> {
        if !valid_id(&self.operation_id)
            || !valid_revision(&self.topology_revision)
            || self.lease.as_deref().is_some_and(|v| !valid_lease(v))
            || (self.restored && self.lease.is_none())
        {
            return Err("invalid_obligation");
        }
        self.configuration.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Snapshot,
    Status,
    Apply(RecoveryObligation),
    Restore(RecoveryObligation),
    Recover(RecoveryObligation),
}

impl Request {
    fn payload(&self) -> Result<Value, &'static str> {
        match self {
            Self::Snapshot => Ok(json!({"action":"snapshot"})),
            Self::Status => Ok(json!({"action":"status"})),
            Self::Apply(o) => {
                o.validate()?;
                if o.lease.is_some() || o.restored {
                    return Err("invalid_obligation");
                }
                Ok(
                    json!({"action":"apply","configuration":o.configuration,"expected_topology_revision":o.topology_revision,"operation_id":o.operation_id}),
                )
            }
            Self::Restore(o) | Self::Recover(o) => {
                o.validate()?;
                let lease = o.lease.as_ref().ok_or("missing_lease")?;
                if o.restored {
                    return Err("already_restored");
                }
                Ok(
                    json!({"action":if matches!(self, Self::Restore(_)) {"restore"} else {"recover"},"lease":lease}),
                )
            }
        }
    }
    fn obligation(&self) -> Option<&RecoveryObligation> {
        match self {
            Self::Apply(o) | Self::Restore(o) | Self::Recover(o) => Some(o),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Snapshot {
        configuration: Configuration,
        topology_revision: String,
    },
    Status {
        state: String,
        owned_by_caller: bool,
        lease: Option<String>,
        operation_id: Option<String>,
    },
    Applied {
        lease: String,
    },
    /// Apply was not confirmed, but the service returned a recoverable lease.
    RecoveryRequired {
        lease: String,
    },
    Restored {
        lease: String,
    },
    ProviderError {
        code: String,
        recovery_required: bool,
        lease: Option<String>,
    },
}
#[derive(Clone, Debug, PartialEq)]
pub enum Progress {
    Waiting,
    Complete(Outcome),
    Rejected(String),
    Unknown,
}

/// At most one broker command per poll. Mutation calls require a persistence
/// callback that atomically stores each obligation before acknowledging success.
pub struct PendingCall {
    request: Request,
    command: Command,
    deadline_ms: u64,
    request_id: Option<u64>,
    failures: u8,
    uncertain_admission: bool,
    initial_persisted: bool,
    result: Option<Outcome>,
    finished: Option<Progress>,
}
impl PendingCall {
    pub fn new(
        request: Request,
        broker_operation_id: String,
        parent: Option<u64>,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        if !valid_id(&broker_operation_id) || !(1..=30_000).contains(&timeout_ms) {
            return Err("invalid_operation");
        }
        let payload = request.payload()?;
        Ok(Self {
            request,
            command: Command::Request {
                service: SERVICE.into(),
                payload,
                timeout_ms,
                operation_id: broker_operation_id,
                parent,
            },
            deadline_ms: now_ms.saturating_add(timeout_ms),
            request_id: None,
            failures: 0,
            uncertain_admission: false,
            initial_persisted: false,
            result: None,
            finished: None,
        })
    }
    pub fn request_id(&self) -> Option<u64> {
        self.request_id
    }
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
        persist: &mut impl FnMut(&RecoveryObligation) -> Result<(), String>,
    ) -> Progress {
        if let Some(done) = &self.finished {
            return done.clone();
        }
        if now_ms >= self.deadline_ms || self.failures >= MAX_FAILURES {
            return self.finish(Progress::Unknown);
        }
        if !self.initial_persisted {
            if let Some(obligation) = self.request.obligation()
                && persist(obligation).is_err()
            {
                return self.finish(Progress::Unknown);
            }
            self.initial_persisted = true;
        }
        if let Some(id) = self.request_id {
            if let Some(result) = &self.result {
                return match send(Command::ReleaseResult { request: id }) {
                    Ok(Response::Ok) => self.finish(Progress::Complete(result.clone())),
                    _ => {
                        self.failures += 1;
                        Progress::Waiting
                    }
                };
            }
            match send(Command::TakeResult { request: id }) {
                Ok(Response::Pending) => Progress::Waiting,
                Ok(Response::Result { payload }) => {
                    let Some(result) = parse_response(&self.request, &payload) else {
                        return self.finish(Progress::Unknown);
                    };
                    if let Some(obligation) = self.request.obligation() {
                        let mut updated = obligation.clone();
                        match &result {
                            Outcome::Applied { lease } | Outcome::RecoveryRequired { lease } => {
                                updated.lease = Some(lease.clone())
                            }
                            Outcome::Restored { lease } => {
                                updated.lease = Some(lease.clone());
                                updated.restored = true;
                            }
                            Outcome::ProviderError {
                                lease: Some(lease), ..
                            } => updated.lease = Some(lease.clone()),
                            _ => {}
                        }
                        if persist(&updated).is_err() {
                            return self.finish(Progress::Unknown);
                        }
                    }
                    self.result = Some(result);
                    Progress::Waiting
                }
                _ => {
                    self.failures += 1;
                    Progress::Waiting
                }
            }
        } else {
            match send(self.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.request_id = Some(id);
                    self.failures = 0;
                    Progress::Waiting
                }
                Ok(Response::Error { code, .. }) if !self.uncertain_admission => {
                    self.finish(Progress::Rejected(code))
                }
                _ => {
                    self.uncertain_admission = true;
                    self.failures += 1;
                    Progress::Waiting
                }
            }
        }
    }
    fn finish(&mut self, progress: Progress) -> Progress {
        self.finished = Some(progress.clone());
        progress
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'/')
        })
}
fn valid_lease(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|b| b.is_ascii_graphic())
}
fn valid_revision(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn optional_string(value: Option<&Value>) -> Option<Option<String>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(s)) if valid_lease(s) => Some(Some(s.clone())),
        _ => None,
    }
}
fn parse_response(request: &Request, payload: &Value) -> Option<Outcome> {
    if !payload.get("ok")?.as_bool()? {
        let code = payload.get("error")?.get("code")?.as_str()?;
        if !valid_lease(code) {
            return None;
        }
        let recovery_required = match payload.get("recovery_required") {
            None => false,
            Some(v) => v.as_bool()?,
        };
        let lease = optional_string(payload.get("lease"))?;
        if recovery_required && lease.is_none() {
            return None;
        }
        if let Request::Restore(o) | Request::Recover(o) = request
            && lease.is_some()
            && lease != o.lease
        {
            return None;
        }
        return Some(Outcome::ProviderError {
            code: code.to_owned(),
            recovery_required,
            lease,
        });
    }
    match request {
        Request::Snapshot => {
            let configuration: Configuration =
                serde_json::from_value(payload.get("configuration")?.clone()).ok()?;
            configuration.validate().ok()?;
            let topology_revision = payload.get("topology_revision")?.as_str()?.to_owned();
            if !valid_revision(&topology_revision) {
                return None;
            }
            Some(Outcome::Snapshot {
                configuration,
                topology_revision,
            })
        }
        Request::Status => {
            let state = payload.get("state")?.as_str()?;
            if !matches!(state, "idle" | "leased" | "recovery_required") {
                return None;
            }
            let owned_by_caller = payload.get("owned_by_caller")?.as_bool()?;
            let lease = optional_string(payload.get("lease"))?;
            let operation_id = optional_string(payload.get("operation_id"))?;
            if (!owned_by_caller && (lease.is_some() || operation_id.is_some()))
                || (owned_by_caller && lease.is_none())
                || (state == "idle" && owned_by_caller)
            {
                return None;
            }
            Some(Outcome::Status {
                state: state.into(),
                owned_by_caller,
                lease,
                operation_id,
            })
        }
        Request::Apply(o) => {
            if payload.get("operation_id")?.as_str()? != o.operation_id {
                return None;
            }
            let lease = payload.get("lease")?.as_str()?;
            if !valid_lease(lease) {
                return None;
            }
            if payload.get("applied")?.as_bool()? {
                Some(Outcome::Applied {
                    lease: lease.into(),
                })
            } else if payload.get("state")?.as_str()? == "recovery_required" {
                Some(Outcome::RecoveryRequired {
                    lease: lease.into(),
                })
            } else {
                None
            }
        }
        Request::Restore(o) | Request::Recover(o) => {
            let lease = payload.get("lease")?.as_str()?;
            if payload.get("restored")?.as_bool()? && o.lease.as_deref() == Some(lease) {
                Some(Outcome::Restored {
                    lease: lease.into(),
                })
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn obligation() -> RecoveryObligation {
        RecoveryObligation::new(
            "physical.1".into(),
            Configuration {
                displays: vec![DisplaySetting {
                    id: "monitor-1".into(),
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

    #[test]
    fn apply_persists_before_dispatch_and_retains_exact_lease() {
        let mut call = PendingCall::new(
            Request::Apply(obligation()),
            "broker.apply.1".into(),
            Some(9),
            1000,
            0,
        )
        .unwrap();
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 7 }),
            Ok(Response::Result {
                payload: json!({"ok":true,"applied":true,"operation_id":"physical.1","lease":"lease-1"}),
            }),
            Ok(Response::Ok),
        ]);
        let mut commands = Vec::new();
        let mut records = Vec::new();
        let mut send = |command| {
            commands.push(command);
            replies.pop_front().unwrap()
        };
        let mut persist = |record: &RecoveryObligation| {
            records.push(record.clone());
            Ok(())
        };
        assert_eq!(call.poll(0, &mut send, &mut persist), Progress::Waiting);
        assert_eq!(call.poll(1, &mut send, &mut persist), Progress::Waiting);
        assert_eq!(
            call.poll(2, &mut send, &mut persist),
            Progress::Complete(Outcome::Applied {
                lease: "lease-1".into()
            })
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].lease, None);
        assert_eq!(records[1].lease.as_deref(), Some("lease-1"));
        match &commands[0] {
            Command::Request {
                service,
                payload,
                parent,
                ..
            } => {
                assert_eq!(service, SERVICE);
                assert_eq!(*parent, Some(9));
                assert_eq!(payload["action"], "apply");
                assert_eq!(payload["operation_id"], "physical.1");
                assert_eq!(
                    payload["expected_topology_revision"],
                    obligation().topology_revision
                );
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn persistence_failure_prevents_dispatch_and_lease_failure_is_unknown() {
        let mut call = PendingCall::new(
            Request::Apply(obligation()),
            "broker.1".into(),
            None,
            1000,
            0,
        )
        .unwrap();
        let mut sent = false;
        assert_eq!(
            call.poll(
                0,
                &mut |_| {
                    sent = true;
                    Ok(Response::Ok)
                },
                &mut |_| Err("disk".into())
            ),
            Progress::Unknown
        );
        assert!(!sent);
        let mut call = PendingCall::new(
            Request::Apply(obligation()),
            "broker.2".into(),
            None,
            1000,
            0,
        )
        .unwrap();
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 2 }),
            Ok(Response::Result {
                payload: json!({"ok":true,"applied":true,"operation_id":"physical.1","lease":"lease-1"}),
            }),
        ]);
        let mut count = 0;
        let mut persist = |_: &RecoveryObligation| {
            count += 1;
            if count == 1 {
                Ok(())
            } else {
                Err("disk".into())
            }
        };
        let mut send = |_| replies.pop_front().unwrap();
        assert_eq!(call.poll(0, &mut send, &mut persist), Progress::Waiting);
        assert_eq!(call.poll(1, &mut send, &mut persist), Progress::Unknown);
        assert_eq!(call.request_id(), Some(2));
    }

    #[test]
    fn restore_only_marks_durable_completion_for_matching_lease() {
        let mut o = obligation();
        o.lease = Some("lease-1".into());
        assert!(
            parse_response(
                &Request::Restore(o.clone()),
                &json!({"ok":true,"restored":true,"lease":"other"})
            )
            .is_none()
        );
        let mut call =
            PendingCall::new(Request::Recover(o), "broker.recover".into(), None, 1000, 0).unwrap();
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 8 }),
            Ok(Response::Result {
                payload: json!({"ok":true,"restored":true,"lease":"lease-1"}),
            }),
            Ok(Response::Ok),
        ]);
        let mut records = Vec::new();
        let mut persist = |r: &RecoveryObligation| {
            records.push(r.clone());
            Ok(())
        };
        let mut send = |_| replies.pop_front().unwrap();
        assert_eq!(call.poll(0, &mut send, &mut persist), Progress::Waiting);
        assert_eq!(call.poll(1, &mut send, &mut persist), Progress::Waiting);
        assert_eq!(
            call.poll(2, &mut send, &mut persist),
            Progress::Complete(Outcome::Restored {
                lease: "lease-1".into()
            })
        );
        assert!(records.last().unwrap().restored);
    }

    #[test]
    fn retry_and_status_do_not_assume_effect_or_foreign_ownership() {
        let mut call = PendingCall::new(
            Request::Apply(obligation()),
            "broker.3".into(),
            None,
            1000,
            0,
        )
        .unwrap();
        let mut commands = Vec::new();
        let mut send = |c| {
            commands.push(c);
            Err("lost".into())
        };
        let mut persist = |_: &RecoveryObligation| Ok(());
        for time in 0..3 {
            assert_eq!(call.poll(time, &mut send, &mut persist), Progress::Waiting);
        }
        assert_eq!(call.poll(3, &mut send, &mut persist), Progress::Unknown);
        assert!(commands.iter().all(
            |c| matches!(c, Command::Request { operation_id, .. } if operation_id == "broker.3")
        ));
        assert!(parse_response(&Request::Status, &json!({"ok":true,"state":"leased","owned_by_caller":false,"lease":"foreign","operation_id":null})).is_none());
        let retry = parse_response(
            &Request::Apply(obligation()),
            &json!({"ok":true,"applied":false,"state":"recovery_required","operation_id":"physical.1","lease":"lease-1"}),
        );
        assert!(matches!(retry, Some(Outcome::RecoveryRequired { .. })));
    }

    #[test]
    fn rejects_invalid_configuration_and_revision() {
        let mut o = obligation();
        o.configuration.displays[0].refresh.denominator = 0;
        assert!(PendingCall::new(Request::Apply(o), "broker.4".into(), None, 1000, 0).is_err());
        assert!(
            RecoveryObligation::new(
                "physical.1".into(),
                obligation().configuration,
                "bad".into()
            )
            .is_err()
        );
    }
}
