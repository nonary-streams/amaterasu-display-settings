//! Recovery-only reconciliation of a persisted resize; never resubmits effects.
use crate::{
    resize_store::{self, DurableResizeStore, ResizeRecordState},
    session_resize::{ResizeIntent, ResizeStore, ResizeStoreCommand, ResizeStoreProgress},
    virtual_callback::{GuardProgress, VirtualObligation},
    virtual_display::{self, CallProgress, DisplayOutcome, DisplayReference, DisplayRequest},
};
use amaterasu_module_sdk::{
    Command, ModuleResult, Response,
    extension_api::{LifecycleTarget, ProviderRequest},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Verifies a fresh coordinator recovery admission for the exact saved intent,
/// canonical session and retired consumers. Called before status and finish.
pub trait RecoveryGuard {
    fn poll(
        &mut self,
        intent: &ResizeIntent,
        session: &LifecycleTarget,
        now: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> GuardProgress;
}
#[derive(Clone, Debug, PartialEq)]
pub enum RecoveryProgress {
    Waiting,
    Recovered(Box<VirtualObligation>),
    RecoveryRequired,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Load,
    GuardStatus,
    Status,
    Commit,
    Validate,
    GuardFinish,
    Finish,
    GuardPublish,
    Done,
}
pub struct ResizeRecovery {
    target: LifecycleTarget,
    expected_request: ProviderRequest,
    parent: Option<u64>,
    deadline: u64,
    nonce: String,
    phase: Phase,
    command: Command,
    id: Option<u64>,
    reply: Option<Value>,
    intent: Option<ResizeIntent>,
    updated: Option<VirtualObligation>,
    committed: bool,
    status_polls: u8,
    store: Option<DurableResizeStore>,
    call: Option<virtual_display::PendingCall>,
}
impl ResizeRecovery {
    /// `verify_target` must authenticate a coordinator-issued recovery request
    /// and exact canonical target; saved intent is separately checked by guard.
    pub fn new(
        caller: &str,
        target: LifecycleTarget,
        expected_request: ProviderRequest,
        parent: Option<u64>,
        timeout: u64,
        now: u64,
        verify_target: impl FnOnce(&LifecycleTarget) -> bool,
    ) -> Result<Self, &'static str> {
        if caller != "amaterasu.session-lifecycle"
            || !matches!(target, LifecycleTarget::Session { .. })
            || timeout == 0
            || amaterasu_module_sdk::extension_api::validate_provider_request(&expected_request)
                .is_err()
            || !verify_target(&target)
        {
            return Err("recovery_not_authorized");
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| "random_unavailable")?;
        let nonce: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let key = format!(
            "virtual-obligation/v1/target-{:x}",
            Sha256::digest(serde_json::to_vec(&target).map_err(|_| "invalid_target")?)
        );
        let timeout = timeout.min(30_000);
        let command = Command::Request {
            service: "amaterasu.state/1".into(),
            payload: json!({"action":"get","key":key}),
            operation_id: format!("resize-recover.{nonce}.load"),
            parent,
            timeout_ms: timeout,
        };
        Ok(Self {
            target,
            expected_request,
            parent,
            deadline: now.saturating_add(timeout),
            nonce,
            phase: Phase::Load,
            command,
            id: None,
            reply: None,
            intent: None,
            updated: None,
            committed: false,
            status_polls: 0,
            store: None,
            call: None,
        })
    }
    fn fail(&mut self) -> RecoveryProgress {
        self.phase = Phase::Done;
        RecoveryProgress::RecoveryRequired
    }
    fn call(
        &self,
        request: DisplayRequest,
        label: &str,
        now: u64,
    ) -> Result<virtual_display::PendingCall, &'static str> {
        virtual_display::PendingCall::new(
            request,
            format!("resize-recover.{}.{}", self.nonce, label),
            self.parent,
            self.deadline.saturating_sub(now).min(30_000),
            now,
        )
    }
    pub fn poll(
        &mut self,
        now: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
        guard: &mut impl RecoveryGuard,
    ) -> RecoveryProgress {
        if now >= self.deadline || self.phase == Phase::Done {
            return self.fail();
        }
        match self.phase {
            Phase::Load => {
                if let Some(id) = self.id {
                    if self.reply.is_none() {
                        match send(Command::TakeResult { request: id }) {
                            Ok(Response::Pending) => {}
                            Ok(Response::Result { payload }) => self.reply = Some(payload),
                            _ => return self.fail(),
                        }
                        return RecoveryProgress::Waiting;
                    }
                    if !matches!(
                        send(Command::ReleaseResult { request: id }),
                        Ok(Response::Ok)
                    ) {
                        return self.fail();
                    }
                    let value = self.reply.take().expect("checked");
                    if value["ok"] != true || value["found"] != true {
                        return self.fail();
                    }
                    let Ok(envelope) = resize_store::decode_envelope(value["value"].clone()) else {
                        return self.fail();
                    };
                    let (intent, updated, committed) = match envelope.active {
                        Some(active) => (
                            active.intent,
                            active.updated,
                            active.state == ResizeRecordState::Committed,
                        ),
                        None => {
                            let Some(last) = envelope.lineage.last() else {
                                return self.fail();
                            };
                            if last.updated != envelope.obligation
                                || last.provider_sequence != self.expected_request.provider_sequence
                                || last.provider_operation_id != self.expected_request.operation_id
                                || resize_store::request_digest(&self.expected_request)
                                    .ok()
                                    .as_deref()
                                    != Some(&last.request_digest)
                            {
                                return self.fail();
                            }
                            let Some(value) = self
                                .expected_request
                                .approved_plan
                                .as_ref()
                                .and_then(|p| p.constraints.pointer("/virtual_reconfigure/desired"))
                                .cloned()
                            else {
                                return self.fail();
                            };
                            let Ok(desired) = serde_json::from_value(value) else {
                                return self.fail();
                            };
                            let intent = ResizeIntent {
                                request: self.expected_request.clone(),
                                session_target: last.session_target.clone(),
                                prior: last.prior.clone(),
                                desired,
                                operation_id: last.native_operation_id.clone(),
                            };
                            if !resize_store::valid_update(&intent, &last.updated) {
                                return self.fail();
                            }
                            (intent, Some(last.updated.clone()), true)
                        }
                    };
                    if intent.session_target != self.target
                        || intent.request != self.expected_request
                    {
                        return self.fail();
                    }
                    self.committed = committed;
                    self.updated = updated;
                    let Ok(store) = DurableResizeStore::new(
                        "amaterasu.session-lifecycle",
                        intent.clone(),
                        format!("recover.{}", self.nonce),
                        self.parent,
                        self.deadline.saturating_sub(now).min(30_000),
                        |_| true,
                    ) else {
                        return self.fail();
                    };
                    self.intent = Some(intent);
                    self.store = Some(store);
                    self.phase = Phase::GuardStatus;
                    return RecoveryProgress::Waiting;
                }
                match send(self.command.clone()) {
                    Ok(Response::Accepted { id }) => self.id = Some(id),
                    _ => return self.fail(),
                };
                RecoveryProgress::Waiting
            }
            Phase::GuardStatus | Phase::GuardFinish => {
                let intent = self.intent.as_ref().expect("loaded");
                match guard.poll(intent, &self.target, now, send) {
                    GuardProgress::Waiting => RecoveryProgress::Waiting,
                    GuardProgress::Authorized => {
                        self.phase = if self.phase == Phase::GuardStatus {
                            Phase::Status
                        } else {
                            Phase::Finish
                        };
                        RecoveryProgress::Waiting
                    }
                    _ => self.fail(),
                }
            }
            Phase::Status => {
                if self.call.is_none() {
                    let intent = self.intent.as_ref().expect("loaded");
                    let Some(borrow) = intent.prior.borrow.as_ref() else {
                        return self.fail();
                    };
                    let request = DisplayRequest::ReconfigureStatus {
                        reference: DisplayReference {
                            identity: intent.prior.identity.clone(),
                            reference_id: intent.prior.reference_id.clone(),
                        },
                        operation_id: intent.operation_id.clone(),
                        borrow_id: borrow.borrow_id.clone(),
                        domain_id: borrow.mutation_domain.id.clone(),
                        revision: borrow.mutation_domain.revision,
                    };
                    if self.status_polls >= 16 {
                        return self.fail();
                    }
                    self.status_polls += 1;
                    let Ok(call) =
                        self.call(request, &format!("status-{}", self.status_polls), now)
                    else {
                        return self.fail();
                    };
                    self.call = Some(call);
                }
                if let Some(DisplayOutcome::Borrowed(borrow)) =
                    self.call.as_ref().and_then(|c| c.tentative())
                {
                    let Some(updated) = resize_store::recovered_obligation(
                        self.intent.as_ref().expect("loaded"),
                        borrow.clone(),
                    ) else {
                        return self.fail();
                    };
                    if self.committed && self.updated.as_ref() != Some(&updated) {
                        return self.fail();
                    }
                    self.updated = Some(updated);
                    if !self.committed {
                        self.phase = Phase::Commit;
                        return RecoveryProgress::Waiting;
                    }
                }
                if self
                    .call
                    .as_ref()
                    .is_some_and(|call| call.request_id().is_none())
                {
                    match guard.poll(
                        self.intent.as_ref().expect("loaded"),
                        &self.target,
                        now,
                        send,
                    ) {
                        GuardProgress::Waiting => return RecoveryProgress::Waiting,
                        GuardProgress::Authorized => {}
                        _ => return self.fail(),
                    }
                }
                match self.call.as_mut().expect("call").poll(now, send) {
                    CallProgress::Waiting => RecoveryProgress::Waiting,
                    CallProgress::Complete(DisplayOutcome::ReconfigurePending) => {
                        self.call = None;
                        self.phase = Phase::GuardStatus;
                        RecoveryProgress::Waiting
                    }
                    CallProgress::Complete(DisplayOutcome::Borrowed(_)) if self.committed => {
                        self.call = None;
                        self.phase = Phase::Validate;
                        RecoveryProgress::Waiting
                    }
                    _ => self.fail(),
                }
            }
            Phase::Commit => {
                let store = self.store.as_mut().expect("store");
                store.advance(now, send);
                match store.poll(&ResizeStoreCommand::Commit {
                    intent: self.intent.as_ref().expect("loaded").clone(),
                    updated: self.updated.as_ref().expect("observed").clone(),
                }) {
                    ResizeStoreProgress::Waiting => RecoveryProgress::Waiting,
                    ResizeStoreProgress::Applied => {
                        self.committed = true;
                        self.phase = Phase::Status;
                        RecoveryProgress::Waiting
                    }
                    _ => self.fail(),
                }
            }
            Phase::Validate => {
                if self.call.is_none() {
                    let updated = self.updated.as_ref().expect("observed");
                    let Some(borrow) = updated.borrow.as_ref() else {
                        return self.fail();
                    };
                    let request = DisplayRequest::ValidateBorrow {
                        reference: DisplayReference {
                            identity: updated.identity.clone(),
                            reference_id: updated.reference_id.clone(),
                        },
                        borrow_id: borrow.borrow_id.clone(),
                    };
                    let Ok(call) = self.call(request, "validate", now) else {
                        return self.fail();
                    };
                    self.call = Some(call);
                }
                match self.call.as_mut().expect("call").poll(now, send) {
                    CallProgress::Waiting => RecoveryProgress::Waiting,
                    CallProgress::Complete(DisplayOutcome::Borrowed(b))
                        if self.updated.as_ref().and_then(|u| u.borrow.as_ref()) == Some(&b) =>
                    {
                        self.call = None;
                        self.phase = Phase::GuardFinish;
                        RecoveryProgress::Waiting
                    }
                    _ => self.fail(),
                }
            }
            Phase::Finish => {
                let store = self.store.as_mut().expect("store");
                store.advance(now, send);
                match store.poll(&ResizeStoreCommand::Finish {
                    intent: self.intent.as_ref().expect("loaded").clone(),
                    updated: self.updated.as_ref().expect("observed").clone(),
                }) {
                    ResizeStoreProgress::Waiting => RecoveryProgress::Waiting,
                    ResizeStoreProgress::Applied => {
                        self.phase = Phase::GuardPublish;
                        RecoveryProgress::Waiting
                    }
                    _ => self.fail(),
                }
            }
            Phase::GuardPublish => match guard.poll(
                self.intent.as_ref().expect("loaded"),
                &self.target,
                now,
                send,
            ) {
                GuardProgress::Waiting => RecoveryProgress::Waiting,
                GuardProgress::Authorized => {
                    self.phase = Phase::Done;
                    RecoveryProgress::Recovered(Box::new(
                        self.updated.as_ref().expect("observed").clone(),
                    ))
                }
                _ => self.fail(),
            },
            Phase::Done => self.fail(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        resize_store::{ResizeEnvelope, ResizeRecord},
        virtual_callback::GuardProgress,
    };
    struct Guard {
        remaining: usize,
    }
    impl RecoveryGuard for Guard {
        fn poll(
            &mut self,
            _: &ResizeIntent,
            _: &LifecycleTarget,
            _: u64,
            _: &mut impl FnMut(Command) -> ModuleResult<Response>,
        ) -> GuardProgress {
            if self.remaining > 0 {
                self.remaining -= 1;
                GuardProgress::Authorized
            } else {
                GuardProgress::Rejected
            }
        }
    }
    struct Fake {
        state: Value,
        revision: u64,
        reply: Value,
        id: u64,
        status_id: u64,
        calls: Vec<String>,
        pending: usize,
        status_success: bool,
        transports: Vec<String>,
        status_released_before_commit: bool,
    }
    impl Fake {
        fn send(&mut self, command: Command) -> ModuleResult<Response> {
            match command {
                Command::Request {
                    service,
                    payload,
                    operation_id,
                    ..
                } => {
                    self.id += 1;
                    let action = payload["action"].as_str().unwrap();
                    self.calls.push(format!("{service}:{action}"));
                    self.reply = if service == "amaterasu.state/1" {
                        match action {
                            "get" => {
                                json!({"ok":true,"found":true,"revision":self.revision,"value":self.state})
                            }
                            "set"
                                if payload["expected_revision"].as_u64() == Some(self.revision) =>
                            {
                                self.state = payload["value"].clone();
                                self.revision += 1;
                                json!({"ok":true,"revision":self.revision})
                            }
                            _ => json!({"ok":false,"error":{"code":"revision_conflict"}}),
                        }
                    } else if action == "reconfigure_status" {
                        self.status_id = self.id;
                        self.transports.push(operation_id);
                        self.status_success = self.pending == 0;
                        if self.pending > 0 {
                            self.pending -= 1;
                            json!({"ok":true,"state":"pending","operation_id":payload["operation_id"]})
                        } else {
                            let (_, updated) = crate::resize_store::tests::fixture();
                            let b = updated.borrow.unwrap();
                            json!({"ok":true,"state":"succeeded","operation_id":payload["operation_id"],"borrow_id":b.borrow_id,"observed_output":b.observed_output,"mutation_domain":b.mutation_domain})
                        }
                    } else if action == "validate_borrow" {
                        let (_, updated) = crate::resize_store::tests::fixture();
                        let b = updated.borrow.unwrap();
                        json!({"ok":true,"borrow_id":b.borrow_id,"observed_output":b.observed_output,"mutation_domain":b.mutation_domain})
                    } else {
                        panic!("unexpected native mutation")
                    };
                    Ok(Response::Accepted { id: self.id })
                }
                Command::TakeResult { .. } => Ok(Response::Result {
                    payload: self.reply.clone(),
                }),
                Command::ReleaseResult { request } => {
                    if request == self.status_id
                        && self.status_success
                        && self.state["active"]["state"] != "committed"
                        && self.state["lineage"].as_array().is_none_or(Vec::is_empty)
                    {
                        self.status_released_before_commit = true;
                    }
                    Ok(Response::Ok)
                }
                _ => panic!("unexpected"),
            }
        }
    }
    fn run(committed: bool, pending: usize, allowed: usize) -> (RecoveryProgress, Fake) {
        let (intent, updated) = crate::resize_store::tests::fixture();
        let active = ResizeRecord {
            intent: intent.clone(),
            updated: committed.then_some(updated.clone()),
            state: if committed {
                ResizeRecordState::Committed
            } else {
                ResizeRecordState::Pending
            },
        };
        let state = serde_json::to_value(ResizeEnvelope {
            format_version: 1,
            obligation: if committed {
                updated
            } else {
                intent.prior.clone()
            },
            active: Some(active),
            checkpoint: None,
            lineage: vec![],
        })
        .unwrap();
        let mut fake = Fake {
            state,
            revision: 1,
            reply: Value::Null,
            id: 0,
            status_id: 0,
            calls: vec![],
            pending,
            status_success: false,
            transports: vec![],
            status_released_before_commit: false,
        };
        let mut recovery = ResizeRecovery::new(
            "amaterasu.session-lifecycle",
            intent.session_target,
            intent.request,
            None,
            5000,
            0,
            |_| true,
        )
        .unwrap();
        let mut guard = Guard { remaining: allowed };
        for now in 0..100 {
            let progress = recovery.poll(now, &mut |c| fake.send(c), &mut guard);
            if progress != RecoveryProgress::Waiting {
                return (progress, fake);
            }
        }
        panic!("stuck")
    }
    #[test]
    fn pending_and_committed_recover_only_after_status_and_durable_commit() {
        for committed in [false, true] {
            let (result, fake) = run(committed, 0, 20);
            assert!(matches!(result, RecoveryProgress::Recovered(_)));
            assert!(!fake.status_released_before_commit);
            assert!(fake.state["active"].is_null());
            assert_eq!(fake.state["lineage"][0]["provider_operation_id"], "op-2");
            assert!(fake.calls.iter().all(|c| !c.ends_with(":reconfigure")));
        }
    }
    #[test]
    fn pending_native_or_denied_guard_leaves_intent_fenced() {
        let (result, fake) = run(false, 100, 100);
        assert_eq!(result, RecoveryProgress::RecoveryRequired);
        assert_eq!(fake.state["active"]["state"], "pending");
        let (result, fake) = run(false, 0, 0);
        assert_eq!(result, RecoveryProgress::RecoveryRequired);
        assert!(
            fake.calls
                .iter()
                .all(|c| !c.starts_with(virtual_display::SERVICE))
        );
    }
    #[test]
    fn revoked_final_guard_never_publishes_success() {
        let (result, fake) = run(false, 0, 3);
        assert_eq!(result, RecoveryProgress::RecoveryRequired);
        assert!(fake.state["active"].is_null());
        assert_eq!(fake.state["lineage"][0]["provider_operation_id"], "op-2");
    }
    #[test]
    fn pending_polls_use_new_transport_ids_before_success() {
        let (result, fake) = run(false, 2, 20);
        assert!(matches!(result, RecoveryProgress::Recovered(_)));
        assert_eq!(fake.transports.len(), 3);
        assert_ne!(fake.transports[0], fake.transports[1]);
        assert_ne!(fake.transports[1], fake.transports[2]);
    }
    #[test]
    fn finished_checkpoint_recovers_only_matching_original_operation() {
        let (result, mut fake) = run(false, 0, 20);
        assert!(matches!(result, RecoveryProgress::Recovered(_)));
        let (intent, _) = crate::resize_store::tests::fixture();
        let mut recovery = ResizeRecovery::new(
            "amaterasu.session-lifecycle",
            intent.session_target.clone(),
            intent.request.clone(),
            None,
            5000,
            0,
            |_| true,
        )
        .unwrap();
        let mut guard = Guard { remaining: 20 };
        let mut outcome = RecoveryProgress::Waiting;
        for now in 0..100 {
            outcome = recovery.poll(now, &mut |c| fake.send(c), &mut guard);
            if outcome != RecoveryProgress::Waiting {
                break;
            }
        }
        assert!(matches!(outcome, RecoveryProgress::Recovered(_)));
        let count = fake.transports.len();
        let mut wrong = ResizeRecovery::new(
            "amaterasu.session-lifecycle",
            intent.session_target,
            {
                let mut changed = intent.request.clone();
                changed.operation_id = "different".into();
                changed
            },
            None,
            5000,
            0,
            |_| true,
        )
        .unwrap();
        for now in 0..10 {
            outcome = wrong.poll(now, &mut |c| fake.send(c), &mut guard);
            if outcome != RecoveryProgress::Waiting {
                break;
            }
        }
        assert_eq!(outcome, RecoveryProgress::RecoveryRequired);
        assert_eq!(fake.transports.len(), count);
    }
}
