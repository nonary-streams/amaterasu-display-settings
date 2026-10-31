//! Physical display callback engine. Integration must supply authenticated
//! coordinator admission and a genuinely durable, nonblocking store.
use crate::physical_display::{self, Configuration, RecoveryObligation};
use amaterasu_module_sdk::{
    Command, ModuleResult, Response,
    extension_api::{self, LifecyclePhase, ProviderOperation, ProviderRequest, ResourceAccess},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const COORDINATOR: &str = "amaterasu.session-lifecycle";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PhysicalConstraint {
    provider: String,
    configuration: Configuration,
    expected_topology_revision: String,
    expected_mutation_domain_id: String,
    expected_mutation_domain_revision: u64,
}

/// Commands must be durably and idempotently processed by the integration's
/// state-backed receipt/obligation store. A fake implementation proves only
/// control flow. `Reserve` must atomically bind sequence, operation and request.
#[derive(Clone, Debug, PartialEq)]
pub enum StoreCommand {
    Reserve {
        sequence: u64,
        operation_id: String,
        request: Value,
    },
    Save {
        sequence: u64,
        obligation: RecoveryObligation,
    },
    /// Verify release uses the exact active durable obligation for this target.
    VerifyPrior { obligation: RecoveryObligation },
    Complete {
        sequence: u64,
        operation_id: String,
        result: CallbackResult,
    },
}
#[derive(Clone, Debug, PartialEq)]
pub enum StoreProgress {
    Waiting,
    Reserved,
    /// Existing pending entries must be reconciled, never replayed.
    ExistingPending,
    ExistingComplete(CallbackResult),
    Saved,
    Verified,
    Completed,
    Unknown,
}
pub trait DurableStore {
    /// Repeated identical calls poll one operation. `Saved`, `Reserved`, and
    /// `Completed` assert a durable commit, not merely queued I/O.
    fn poll(&mut self, command: &StoreCommand) -> StoreProgress;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CallbackResult {
    Applied { lease: String },
    Restored { lease: String },
    RecoveryRequired,
    Rejected { reason: String },
}
#[derive(Clone, Debug, PartialEq)]
pub enum CallbackProgress {
    Waiting,
    Complete(CallbackResult),
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserve,
    VerifyPrior,
    InitialSave,
    Physical,
    UpdatedSave,
    Complete,
    Done,
}

pub struct PhysicalCallback {
    sequence: u64,
    operation_id: String,
    request_value: Value,
    obligation: RecoveryObligation,
    saved: RecoveryObligation,
    call: physical_display::PendingCall,
    phase: Phase,
    result: Option<CallbackResult>,
    deadline_ms: u64,
    is_prepare: bool,
    request: ProviderRequest,
    callback_parent: Option<u64>,
}

impl PhysicalCallback {
    /// `verify_admission` must authenticate the broker-selected coordinator and
    /// its recorded admission against this complete request, including plan and
    /// settings revision. Payload fields or an admission ID alone are not authority.
    pub fn new(
        caller: &str,
        request: ProviderRequest,
        prior: Option<RecoveryObligation>,
        verify_admission: impl FnOnce(&ProviderRequest) -> bool,
        now_ms: u64,
        callback_parent: Option<u64>,
    ) -> Result<Self, &'static str> {
        Self::build(
            caller,
            request,
            prior,
            verify_admission,
            now_ms,
            cfg!(windows),
            callback_parent,
        )
    }

    fn build(
        caller: &str,
        request: ProviderRequest,
        prior: Option<RecoveryObligation>,
        verify_admission: impl FnOnce(&ProviderRequest) -> bool,
        now_ms: u64,
        physical_supported: bool,
        callback_parent: Option<u64>,
    ) -> Result<Self, &'static str> {
        if caller != COORDINATOR
            || extension_api::validate_provider_request(&request).is_err()
            || request.operation != ProviderOperation::LifecycleCallback
            || !verify_admission(&request)
        {
            return Err("unauthorized_or_invalid_admission");
        }
        // Linux physical KScreen mutation remains provider-gated.
        if !physical_supported {
            return Err("physical_provider_unsupported");
        }
        let plan = request.approved_plan.as_ref().ok_or("missing_plan")?;
        let physical: PhysicalConstraint = serde_json::from_value(
            plan.constraints
                .get("physical")
                .cloned()
                .ok_or("missing_physical_constraint")?,
        )
        .map_err(|_| "invalid_physical_constraint")?;
        if physical.provider != physical_display::SERVICE
            || physical.configuration.validate().is_err()
        {
            return Err("invalid_physical_constraint");
        }
        if !plan.mutation_domains.iter().any(|domain| {
            domain.domain == physical.expected_mutation_domain_id
                && domain.expected_revision == physical.expected_mutation_domain_revision
                && domain.access == ResourceAccess::Exclusive
        }) {
            return Err("physical_domain_not_admitted");
        }
        // A complete topology can only touch displays explicitly admitted as
        // exclusive resources in the coordinator's execution domain.
        if physical.configuration.displays.len() != plan.resources.len()
            || plan.resources.iter().any(|resource| {
                resource.provider != crate::descriptor::PROVIDER
                    || resource.access != ResourceAccess::Exclusive
                    || resource.execution_domain != request.consumer_requirements.execution_domain
                    || !physical
                        .configuration
                        .displays
                        .iter()
                        .any(|display| display.id == resource.resource_id)
            })
        {
            return Err("physical_target_not_admitted");
        }
        let is_prepare = matches!(
            request.phase,
            LifecyclePhase::SessionPrepare | LifecyclePhase::StreamPrepare
        );
        if is_prepare && callback_parent.is_none() {
            return Err("missing_callback_parent");
        }
        let obligation = if is_prepare {
            if prior.is_some() {
                return Err("unexpected_prior_obligation");
            }
            RecoveryObligation::new(
                request.operation_id.clone(),
                physical.configuration,
                physical.expected_topology_revision,
            )?
            .with_domain(
                physical.expected_mutation_domain_id,
                physical.expected_mutation_domain_revision,
            )?
        } else {
            let prior = prior.ok_or("missing_prior_obligation")?;
            if prior.configuration != physical.configuration
                || prior.topology_revision != physical.expected_topology_revision
                || prior.mutation_domain_id.as_deref()
                    != Some(physical.expected_mutation_domain_id.as_str())
                || prior.mutation_domain_revision
                    != Some(physical.expected_mutation_domain_revision)
                || prior.lease.is_none()
                || prior.restored
            {
                return Err("obligation_mismatch");
            }
            prior
        };
        let action = if is_prepare {
            physical_display::Request::Apply(obligation.clone())
        } else {
            physical_display::Request::Restore(obligation.clone())
        };
        let timeout = request.remaining_ms.min(30_000);
        let call = physical_display::PendingCall::new(
            action,
            format!("physical.{}", request.operation_id),
            if is_prepare { callback_parent } else { None },
            timeout,
            now_ms,
        )?;
        // The coordinator persists the entire frozen request, including remaining_ms.
        let request_value = serde_json::to_value(&request).map_err(|_| "invalid_request")?;
        if serde_json::to_vec(&request_value)
            .map_err(|_| "invalid_request")?
            .len()
            > 4096
        {
            return Err("receipt_request_too_large");
        }
        Ok(Self {
            sequence: request.provider_sequence,
            operation_id: request.operation_id.clone(),
            request_value,
            saved: obligation.clone(),
            obligation,
            call,
            phase: Phase::Reserve,
            result: None,
            deadline_ms: now_ms.saturating_add(timeout),
            is_prepare,
            request,
            callback_parent,
        })
    }

    /// Advances one durable-store operation or one broker command per tick.
    /// On unknown effects the pending receipt and last durable obligation remain
    /// available for authenticated status/recovery; no mutation is replayed.
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
        store: &mut impl DurableStore,
        guard: &mut impl crate::virtual_callback::EffectGuard,
    ) -> CallbackProgress {
        if self.phase != Phase::Done && now_ms >= self.deadline_ms {
            self.result = None;
            self.phase = Phase::Done;
            return CallbackProgress::RecoveryRequired;
        }
        match self.phase {
            Phase::Reserve => {
                let command = StoreCommand::Reserve {
                    sequence: self.sequence,
                    operation_id: self.operation_id.clone(),
                    request: self.request_value.clone(),
                };
                match store.poll(&command) {
                    StoreProgress::Waiting => CallbackProgress::Waiting,
                    StoreProgress::Reserved => {
                        self.phase = if self.is_prepare {
                            Phase::InitialSave
                        } else {
                            Phase::VerifyPrior
                        };
                        CallbackProgress::Waiting
                    }
                    StoreProgress::ExistingComplete(result) => {
                        self.result = Some(result.clone());
                        self.phase = Phase::Done;
                        CallbackProgress::Complete(result)
                    }
                    _ => {
                        self.result = None;
                        self.phase = Phase::Done;
                        CallbackProgress::RecoveryRequired
                    }
                }
            }
            Phase::VerifyPrior => {
                match store.poll(&StoreCommand::VerifyPrior {
                    obligation: self.obligation.clone(),
                }) {
                    StoreProgress::Waiting => CallbackProgress::Waiting,
                    StoreProgress::Verified => {
                        self.phase = Phase::InitialSave;
                        CallbackProgress::Waiting
                    }
                    _ => {
                        self.phase = Phase::Done;
                        CallbackProgress::RecoveryRequired
                    }
                }
            }
            Phase::InitialSave | Phase::UpdatedSave => {
                let command = StoreCommand::Save {
                    sequence: self.sequence,
                    obligation: self.obligation.clone(),
                };
                match store.poll(&command) {
                    StoreProgress::Waiting => CallbackProgress::Waiting,
                    StoreProgress::Saved => {
                        self.saved = self.obligation.clone();
                        self.phase = Phase::Physical;
                        CallbackProgress::Waiting
                    }
                    _ => {
                        self.phase = Phase::Done;
                        CallbackProgress::RecoveryRequired
                    }
                }
            }
            Phase::Physical => {
                if self.is_prepare && self.call.request_id().is_none() {
                    let Some(parent) = self.callback_parent else {
                        self.phase = Phase::Done;
                        return CallbackProgress::RecoveryRequired;
                    };
                    match guard.poll(
                        &self.request,
                        crate::virtual_callback::EffectKind::PhysicalApply,
                        parent,
                        now_ms,
                        send,
                    ) {
                        crate::virtual_callback::GuardProgress::Waiting => {
                            return CallbackProgress::Waiting;
                        }
                        crate::virtual_callback::GuardProgress::Authorized => {}
                        crate::virtual_callback::GuardProgress::Rejected
                        | crate::virtual_callback::GuardProgress::Unknown => {
                            self.phase = Phase::Done;
                            return CallbackProgress::RecoveryRequired;
                        }
                    }
                }
                let saved = &self.saved;
                let mut changed = None;
                let progress = self.call.poll(now_ms, send, &mut |next| {
                    if next != saved {
                        changed = Some(next.clone());
                    }
                    Ok(())
                });
                if let Some(obligation) = changed {
                    self.obligation = obligation;
                    self.phase = Phase::UpdatedSave;
                    return CallbackProgress::Waiting;
                }
                match progress {
                    physical_display::Progress::Waiting => CallbackProgress::Waiting,
                    physical_display::Progress::Complete(physical_display::Outcome::Applied {
                        lease,
                    }) => self.finish_result(CallbackResult::Applied { lease }),
                    physical_display::Progress::Complete(physical_display::Outcome::Restored {
                        lease,
                    }) => self.finish_result(CallbackResult::Restored { lease }),
                    physical_display::Progress::Rejected(reason) => {
                        self.finish_result(CallbackResult::Rejected { reason })
                    }
                    _ => {
                        self.phase = Phase::Done;
                        CallbackProgress::RecoveryRequired
                    }
                }
            }
            Phase::Complete => {
                let result = self
                    .result
                    .clone()
                    .expect("result is set before completion");
                let command = StoreCommand::Complete {
                    sequence: self.sequence,
                    operation_id: self.operation_id.clone(),
                    result: result.clone(),
                };
                match store.poll(&command) {
                    StoreProgress::Waiting => CallbackProgress::Waiting,
                    StoreProgress::Completed => {
                        self.phase = Phase::Done;
                        CallbackProgress::Complete(result)
                    }
                    _ => {
                        self.result = None;
                        self.phase = Phase::Done;
                        CallbackProgress::RecoveryRequired
                    }
                }
            }
            Phase::Done => self.result.clone().map_or(
                CallbackProgress::RecoveryRequired,
                CallbackProgress::Complete,
            ),
        }
    }
    fn finish_result(&mut self, result: CallbackResult) -> CallbackProgress {
        self.result = Some(result);
        self.phase = Phase::Complete;
        CallbackProgress::Waiting
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;

    fn request() -> ProviderRequest {
        serde_json::from_value(json!({
            "provider_sequence":1,"operation":"lifecycle_callback","version":1,
            "transition_id":"transition-1","operation_id":"operation-1",
            "target":{"kind":"stream","host_epoch":"epoch-1","session_id":"session-1","stream_id":"stream-1","generation":1},
            "phase":"stream.prepare","settings_revision":"settings-1","settings":{},"intent":"initial","reason":null,"requested_video":null,
            "consumer_requirements":{"execution_domain":"desktop","capture_providers":["capture"],"selector_schemas":["selector"]},
            "remaining_ms":5000,"plan_revision":1,"admission_id":"admission-1",
            "approved_plan":{"plan_id":"plan-1","revision":1,"resources":[{"provider":"nonary.display-settings","resource_id":"display-1","incarnation":null,"expected_revision":null,"execution_domain":"desktop","mutation_domains":[],"access":"exclusive"}],
            "mutation_domains":[{"domain":"physical_provider_session:abc","expected_revision":2,"borrowers":{},"access":"exclusive"}],"required_capabilities":[],"constraints":{"physical":{"expected_mutation_domain_id":"physical_provider_session:abc","expected_mutation_domain_revision":2,"provider":"amaterasu.display/1","configuration":{"displays":[{"id":"display-1","width":1920,"height":1080,"refresh":{"numerator":60,"denominator":1},"x":0,"y":0}]},"expected_topology_revision":"0123456789abcdef0123456789abcdef"}},"obligations":[],"affected_consumers":[],"consumer_change":"reconnect_required","candidate_constraint":null,"allowed_degradation":[]}
        })).unwrap()
    }
    struct AllowGuard;
    impl crate::virtual_callback::EffectGuard for AllowGuard {
        fn poll(
            &mut self,
            _: &ProviderRequest,
            _: crate::virtual_callback::EffectKind,
            _: u64,
            _: u64,
            _: &mut impl FnMut(Command) -> ModuleResult<Response>,
        ) -> crate::virtual_callback::GuardProgress {
            crate::virtual_callback::GuardProgress::Authorized
        }
    }
    struct DenyGuard;
    impl crate::virtual_callback::EffectGuard for DenyGuard {
        fn poll(
            &mut self,
            _: &ProviderRequest,
            _: crate::virtual_callback::EffectKind,
            _: u64,
            _: u64,
            _: &mut impl FnMut(Command) -> ModuleResult<Response>,
        ) -> crate::virtual_callback::GuardProgress {
            crate::virtual_callback::GuardProgress::Rejected
        }
    }
    struct FakeStore {
        replies: VecDeque<StoreProgress>,
        commands: Vec<StoreCommand>,
    }
    impl DurableStore for FakeStore {
        fn poll(&mut self, command: &StoreCommand) -> StoreProgress {
            self.commands.push(command.clone());
            self.replies.pop_front().unwrap()
        }
    }
    #[test]
    fn apply_waits_for_each_durable_ack_before_dispatch_and_completion() {
        let mut callback =
            PhysicalCallback::build(COORDINATOR, request(), None, |_| true, 0, true, Some(99))
                .unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([
                StoreProgress::Reserved,
                StoreProgress::Saved,
                StoreProgress::Waiting,
                StoreProgress::Saved,
                StoreProgress::Completed,
            ]),
            commands: vec![],
        };
        let mut responses = VecDeque::from([
            Ok(Response::Accepted { id: 4 }),
            Ok(Response::Result {
                payload: json!({"ok":true,"applied":true,"operation_id":"operation-1","lease":"lease-1"}),
            }),
            Ok(Response::Ok),
        ]);
        let mut commands = Vec::new();
        let mut guard = AllowGuard;
        let mut send = |command: Command| {
            commands.push(command);
            responses.pop_front().unwrap()
        };
        assert_eq!(
            callback.poll(1, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            callback.poll(2, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            callback.poll(3, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            callback.poll(4, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            callback.poll(5, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            callback.poll(6, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            callback.poll(7, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            callback.poll(8, &mut send, &mut store, &mut guard),
            CallbackProgress::Complete(CallbackResult::Applied {
                lease: "lease-1".into()
            })
        );
        assert!(matches!(
            &commands[..],
            [
                Command::Request { .. },
                Command::TakeResult { .. },
                Command::ReleaseResult { .. }
            ]
        ));
        assert!(
            matches!(&store.commands[1],StoreCommand::Save {obligation,..} if obligation.lease.is_none())
        );
        assert!(
            matches!(&store.commands[2],StoreCommand::Save {obligation,..} if obligation.lease.as_deref()==Some("lease-1"))
        );
    }
    #[test]
    fn rejected_admission_and_platform_never_dispatch() {
        assert!(
            PhysicalCallback::build("other", request(), None, |_| true, 0, true, Some(99)).is_err()
        );
        assert!(
            PhysicalCallback::build(COORDINATOR, request(), None, |_| false, 0, true, Some(99))
                .is_err()
        );
        assert!(
            PhysicalCallback::build(COORDINATOR, request(), None, |_| true, 0, false, Some(99))
                .is_err()
        );
        let mut altered = request();
        altered.approved_plan.as_mut().unwrap().resources[0].resource_id = "other".into();
        assert!(
            PhysicalCallback::build(COORDINATOR, altered, None, |_| true, 0, true, Some(99))
                .is_err()
        );
    }
    #[test]
    fn pending_receipt_is_never_replayed() {
        let mut callback =
            PhysicalCallback::build(COORDINATOR, request(), None, |_| true, 0, true, Some(99))
                .unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([StoreProgress::ExistingPending]),
            commands: vec![],
        };
        let mut guard = AllowGuard;
        let mut send = |_: Command| panic!("must not send physical operation");
        assert_eq!(
            callback.poll(1, &mut send, &mut store, &mut guard),
            CallbackProgress::RecoveryRequired
        );
    }
    #[test]
    fn expired_prepare_cannot_apply_after_async_persistence() {
        let mut callback =
            PhysicalCallback::build(COORDINATOR, request(), None, |_| true, 0, true, Some(99))
                .unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([StoreProgress::Reserved, StoreProgress::Saved]),
            commands: vec![],
        };
        let mut guard = DenyGuard;
        let mut send = |_: Command| panic!("stale physical apply must not dispatch");
        assert_eq!(
            callback.poll(1, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            callback.poll(2, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            callback.poll(3, &mut send, &mut store, &mut guard),
            CallbackProgress::RecoveryRequired
        );
    }

    #[test]
    fn failed_lease_persistence_never_releases_result_or_reports_success() {
        let mut callback =
            PhysicalCallback::build(COORDINATOR, request(), None, |_| true, 0, true, Some(99))
                .unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([
                StoreProgress::Reserved,
                StoreProgress::Saved,
                StoreProgress::Unknown,
            ]),
            commands: vec![],
        };
        let mut responses = VecDeque::from([
            Ok(Response::Accepted { id: 4 }),
            Ok(Response::Result {
                payload: json!({"ok":true,"applied":true,"operation_id":"operation-1","lease":"lease-1"}),
            }),
        ]);
        let mut commands = Vec::new();
        let mut guard = AllowGuard;
        let mut send = |command: Command| {
            commands.push(command);
            responses.pop_front().unwrap()
        };
        for tick in 1..=4 {
            assert_eq!(
                callback.poll(tick, &mut send, &mut store, &mut guard),
                CallbackProgress::Waiting
            );
        }
        assert_eq!(
            callback.poll(5, &mut send, &mut store, &mut guard),
            CallbackProgress::RecoveryRequired
        );
        assert_eq!(
            callback.poll(6, &mut send, &mut store, &mut guard),
            CallbackProgress::RecoveryRequired
        );
        assert_eq!(commands.len(), 2);
    }

    #[test]
    fn release_requires_verified_exact_stored_obligation_before_dispatch() {
        let mut req = request();
        req.phase = LifecyclePhase::StreamRelease;
        req.operation_id = "release-1".into();
        let constraint: PhysicalConstraint = serde_json::from_value(
            req.approved_plan.as_ref().unwrap().constraints["physical"].clone(),
        )
        .unwrap();
        let mut obligation = RecoveryObligation::new(
            "operation-1".into(),
            constraint.configuration,
            constraint.expected_topology_revision,
        )
        .unwrap()
        .with_domain(
            constraint.expected_mutation_domain_id,
            constraint.expected_mutation_domain_revision,
        )
        .unwrap();
        obligation.lease = Some("lease-1".into());
        let mut callback = PhysicalCallback::build(
            COORDINATOR,
            req,
            Some(obligation.clone()),
            |_| true,
            0,
            true,
            None,
        )
        .unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([StoreProgress::Reserved, StoreProgress::Unknown]),
            commands: vec![],
        };
        let mut guard = AllowGuard;
        let mut send = |_: Command| panic!("unverified lease must not be used");
        assert_eq!(
            callback.poll(1, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            callback.poll(2, &mut send, &mut store, &mut guard),
            CallbackProgress::RecoveryRequired
        );
        assert!(
            matches!(&store.commands[1], StoreCommand::VerifyPrior { obligation: value } if *value == obligation)
        );
    }
}
