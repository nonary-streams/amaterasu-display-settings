//! Verify an effect callback against the selected coordinator's durable admission.
use amaterasu_module_sdk::extension_api::{LifecycleTarget, ProviderRequest};
use amaterasu_module_sdk::{Command, ModuleResult, Response};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SERVICE: &str = "amaterasu.session-lifecycle/1";
const COORDINATOR: &str = "amaterasu.session-lifecycle";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionIdentity {
    pub host_epoch: String,
    pub provider_sequence: u64,
    pub operation_id: String,
    pub transition_id: String,
    pub fingerprint: String,
    pub target: Value,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verification {
    Pending,
    Verified,
    Rejected,
    Unknown,
}

/// Maintains the same operation identity across uncertain broker admissions.
pub struct PendingVerification {
    identity: AdmissionIdentity,
    command: Command,
    request_id: Option<u64>,
    reply: Option<Value>,
    deadline_ms: u64,
    failures: u8,
    uncertain: bool,
    done: Option<Verification>,
}
impl PendingVerification {
    pub fn from_request(
        caller: &str,
        request: &ProviderRequest,
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        amaterasu_module_sdk::extension_api::validate_provider_request(request)
            .map_err(|_| "invalid_provider_request")?;
        let host_epoch = match &request.target {
            LifecycleTarget::Session { host_epoch, .. }
            | LifecycleTarget::Stream { host_epoch, .. }
            | LifecycleTarget::Validation { host_epoch, .. } => host_epoch.clone(),
        };
        let bytes = serde_json::to_vec(request).map_err(|_| "invalid_provider_request")?;
        let fingerprint = format!("{:x}", Sha256::digest(&bytes));
        let identity = AdmissionIdentity {
            host_epoch,
            provider_sequence: request.provider_sequence,
            operation_id: request.operation_id.clone(),
            transition_id: request.transition_id.clone(),
            fingerprint,
            target: serde_json::to_value(&request.target)
                .map_err(|_| "invalid_provider_request")?,
        };
        Self::new(caller, identity, request.remaining_ms, now_ms)
    }
    fn new(
        caller: &str,
        identity: AdmissionIdentity,
        remaining_ms: u64,
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        if caller != COORDINATOR
            || !valid_id(&identity.host_epoch, 128)
            || !valid_id(&identity.operation_id, 121)
            || !valid_id(&identity.transition_id, 128)
            || identity.fingerprint.len() != 64
            || !identity
                .fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !identity.target.is_object()
            || identity.provider_sequence == 0
            || remaining_ms == 0
        {
            return Err("invalid_coordinator_admission");
        }
        let timeout_ms = remaining_ms.min(30_000);
        // A fresh transport operation is essential: a later guard must not
        // retrieve a cached earlier verification, even after a module restart.
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "random_unavailable")?;
        let nonce = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let command = Command::Request {
            service: SERVICE.into(),
            payload: json!({"operation":"verify_provider_epoch","host_epoch":identity.host_epoch,
                "provider_sequence":identity.provider_sequence,"operation_id":identity.operation_id,
                "transition_id":identity.transition_id,"fingerprint":identity.fingerprint,"target":identity.target}),
            timeout_ms,
            operation_id: format!("verify.{nonce}"),
            parent: None,
        };
        Ok(Self {
            identity,
            command,
            request_id: None,
            reply: None,
            deadline_ms: now_ms.saturating_add(timeout_ms),
            failures: 0,
            uncertain: false,
            done: None,
        })
    }
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> Verification {
        if let Some(done) = self.done {
            return done;
        }
        if now_ms >= self.deadline_ms || self.failures >= 3 {
            return self.finish(Verification::Unknown);
        }
        if let Some(id) = self.request_id {
            if let Some(reply) = self.reply.take() {
                return match send(Command::ReleaseResult { request: id }) {
                    Ok(Response::Ok) => {
                        let verified = reply.get("status").and_then(Value::as_str)
                            == Some("succeeded")
                            && reply.get("host_epoch").and_then(Value::as_str)
                                == Some(self.identity.host_epoch.as_str())
                            && reply.get("provider_sequence").and_then(Value::as_u64)
                                == Some(self.identity.provider_sequence)
                            && reply.get("operation_id").and_then(Value::as_str)
                                == Some(self.identity.operation_id.as_str())
                            && reply.get("transition_id").and_then(Value::as_str)
                                == Some(self.identity.transition_id.as_str())
                            && reply.get("fingerprint").and_then(Value::as_str)
                                == Some(self.identity.fingerprint.as_str())
                            && reply.get("target") == Some(&self.identity.target);
                        self.finish(if verified {
                            Verification::Verified
                        } else {
                            Verification::Rejected
                        })
                    }
                    _ => {
                        self.reply = Some(reply);
                        self.failures += 1;
                        Verification::Pending
                    }
                };
            }
            match send(Command::TakeResult { request: id }) {
                Ok(Response::Pending) => Verification::Pending,
                Ok(Response::Result { payload }) => {
                    self.reply = Some(payload);
                    Verification::Pending
                }
                _ => {
                    self.failures += 1;
                    Verification::Pending
                }
            }
        } else {
            match send(self.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.request_id = Some(id);
                    Verification::Pending
                }
                Ok(Response::Error { .. }) if !self.uncertain => {
                    self.finish(Verification::Rejected)
                }
                _ => {
                    self.uncertain = true;
                    self.failures += 1;
                    Verification::Pending
                }
            }
        }
    }
    fn finish(&mut self, result: Verification) -> Verification {
        self.done = Some(result);
        result
    }
}

fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    fn identity() -> AdmissionIdentity {
        AdmissionIdentity {
            host_epoch: "host-1".into(),
            provider_sequence: 9,
            operation_id: "op-9".into(),
            transition_id: "transition-9".into(),
            fingerprint: "a".repeat(64),
            target: json!({"kind":"session","host_epoch":"host-1","session_id":"s","generation":1}),
        }
    }
    #[test]
    fn only_exact_coordinator_admission_is_verified() {
        for mismatch in [false, true] {
            let mut request = PendingVerification::new(COORDINATOR, identity(), 100, 0).unwrap();
            let mut replies = VecDeque::from([
                Response::Accepted { id: 7 },
                Response::Result {
                    payload: json!({"status":"succeeded","host_epoch":"host-1","provider_sequence":if mismatch { 8 } else { 9 },"operation_id":"op-9","transition_id":"transition-9","fingerprint":"a".repeat(64),"target":{"kind":"session","host_epoch":"host-1","session_id":"s","generation":1}}),
                },
                Response::Ok,
            ]);
            let mut send = |_: Command| Ok(replies.pop_front().unwrap());
            assert_eq!(request.poll(1, &mut send), Verification::Pending);
            assert_eq!(request.poll(2, &mut send), Verification::Pending);
            assert_eq!(
                request.poll(3, &mut send),
                if mismatch {
                    Verification::Rejected
                } else {
                    Verification::Verified
                }
            );
        }
        assert!(PendingVerification::new("other", identity(), 100, 0).is_err());
    }
    #[test]
    fn unknown_transport_never_authorizes_effect() {
        let mut request = PendingVerification::new(COORDINATOR, identity(), 100, 0).unwrap();
        let mut send = |_: Command| Err("lost".into());
        for time in 1..4 {
            assert_eq!(request.poll(time, &mut send), Verification::Pending);
        }
        assert_eq!(request.poll(4, &mut send), Verification::Unknown);
    }
    #[test]
    fn later_guards_get_distinct_transport_ids() {
        let one = PendingVerification::new(COORDINATOR, identity(), 100, 0).unwrap();
        let two = PendingVerification::new(COORDINATOR, identity(), 100, 0).unwrap();
        let (
            Command::Request {
                operation_id: a, ..
            },
            Command::Request {
                operation_id: b, ..
            },
        ) = (one.command, two.command)
        else {
            panic!("unexpected command")
        };
        assert_ne!(a, b);
    }
}
