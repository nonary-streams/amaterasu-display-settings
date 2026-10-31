//! Lifecycle adapter for a caller-owned virtual-display reference. The durable
//! store and authenticated coordinator admission must be supplied by integration.
use crate::virtual_display::{
    self as wire, CallProgress, CreateDisplay, DisplayBorrow, DisplayOutcome, DisplayReference,
    DisplayRequest,
};
use amaterasu_module_sdk::{
    Command, ModuleResult, Response,
    extension_api::{
        self, CaptureBinding, CaptureFallback, LifecyclePhase, LifecycleTarget, ProviderOperation,
        ProviderRequest, ProviderResponse, ResourceAccess, ResourceObligation, ResourceRef,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const COORDINATOR: &str = "amaterasu.session-lifecycle";
const CAPTURE: &str = "amaterasu.capture-pipewire/1";
const SELECTOR: &str = "amaterasu.kwin-wl-output/1";
const MAX_STATUS: u8 = 16;

/// Stable producer identity shared by references to one observed compositor output.
pub(crate) fn producer_incarnation(
    domain_id: &str,
    identity: &str,
    output: &wire::ObservedOutput,
) -> String {
    let bytes = serde_json::to_vec(&(
        domain_id,
        identity,
        &output.protocol,
        &output.compositor_id,
        output.registry_global,
        &output.output_name,
    ))
    .expect("typed output serializes");
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VirtualObligation {
    pub provider_service: String,
    pub identity: String,
    pub reference_id: String,
    pub width: u32,
    pub height: u32,
    pub refresh_millihz: u32,
    pub name: String,
    pub hdr_enabled: bool,
    pub scale: Option<i32>,
    pub layout: String,
    pub domain_id: String,
    pub domain_revision: u64,
    pub geometry_revision: u64,
    pub borrow: Option<DisplayBorrow>,
    pub reference_released: bool,
}
impl VirtualObligation {
    fn reference(&self) -> DisplayReference {
        DisplayReference {
            identity: self.identity.clone(),
            reference_id: self.reference_id.clone(),
        }
    }
    fn create(&self) -> CreateDisplay {
        CreateDisplay {
            reference: self.reference(),
            width: self.width,
            height: self.height,
            refresh_millihz: self.refresh_millihz,
            name: self.name.clone(),
            hdr_enabled: self.hdr_enabled,
            scale: self.scale,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum StoreCommand {
    Reserve {
        sequence: u64,
        operation_id: String,
        request: Value,
    },
    Save {
        sequence: u64,
        obligation: VirtualObligation,
    },
    VerifyPrior {
        obligation: VirtualObligation,
    },
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
    Saved,
    Verified,
    Completed,
    ExistingPending,
    ExistingComplete(CallbackResult),
    Unknown,
}
/// Only acknowledge success after the receipt or ownership journal is durable.
/// ExistingPending requires reconciliation; a store must check request identity.
pub trait DurableVirtualStore {
    fn poll(&mut self, command: &StoreCommand) -> StoreProgress;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectKind {
    Create,
    Borrow,
    PhysicalApply,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardProgress {
    Waiting,
    Authorized,
    Rejected,
    Unknown,
}
/// Revalidate the frozen admission, current generation and live callback parent.
pub trait EffectGuard {
    fn poll(
        &mut self,
        request: &ProviderRequest,
        effect: EffectKind,
        parent: u64,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> GuardProgress;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CallbackResult {
    Prepared {
        candidate: Box<CaptureBinding>,
        obligations: Vec<ResourceObligation>,
    },
    Released,
    Rejected {
        reason: String,
    },
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
    SaveInitial,
    Create,
    Status,
    Borrow,
    SaveBorrow,
    SaveValidated,
    Validate,
    ReleaseBorrow,
    SaveBorrowReleased,
    Remove,
    CleanupStatus,
    SaveReleased,
    Complete,
    Done,
}

pub struct VirtualCallback {
    sequence: u64,
    operation_id: String,
    request: ProviderRequest,
    fingerprint: Value,
    obligation: VirtualObligation,
    phase: Phase,
    call: Option<wire::PendingCall>,
    status_count: u8,
    saved_borrow: bool,
    result: Option<CallbackResult>,
    deadline_ms: u64,
    prepare: bool,
    ready_output: Option<String>,
    callback_parent: Option<u64>,
}
impl VirtualCallback {
    /// The verifier must authenticate the selected coordinator and its durable
    /// admission, exact target, borrower revisions, grants, and capture retirement
    /// on release. A payload admission ID alone is not authority.
    pub fn new(
        caller: &str,
        request: ProviderRequest,
        prior: Option<VirtualObligation>,
        verify_admission: impl FnOnce(&ProviderRequest) -> bool,
        now_ms: u64,
        callback_parent: Option<u64>,
    ) -> Result<Self, &'static str> {
        if caller != COORDINATOR
            || extension_api::validate_provider_request(&request).is_err()
            || request.operation != ProviderOperation::LifecycleCallback
            || !verify_admission(&request)
        {
            return Err("unauthorized_or_invalid_admission");
        }
        let plan = request.approved_plan.as_ref().ok_or("missing_plan")?;
        let mut requested: VirtualObligation = serde_json::from_value(
            plan.constraints
                .get("virtual_display")
                .cloned()
                .ok_or("missing_virtual_constraint")?,
        )
        .map_err(|_| "invalid_virtual_constraint")?;
        if requested.borrow.is_some()
            || requested.reference_released
            || requested.hdr_enabled
            || requested.geometry_revision == 0
            || !matches!(requested.layout.as_str(), "extended" | "exclusive")
        {
            return Err("unsupported_virtual_constraint");
        }
        let binding = plan
            .candidate_constraint
            .as_ref()
            .ok_or("missing_candidate_constraint")?;
        if binding.capture_provider != CAPTURE
            || binding.selector_schema != SELECTOR
            || binding.resource_provider != crate::descriptor::PROVIDER
            || binding.resource_id != requested.identity
            || binding.execution_domain != request.consumer_requirements.execution_domain
            || binding.plan_revision != plan.revision
        {
            return Err("invalid_candidate_constraint");
        }
        if binding.mode.as_ref().is_some_and(|m| {
            m.width != requested.width
                || m.height != requested.height
                || m.refresh_millihz != requested.refresh_millihz
                || m.hdr != requested.hdr_enabled
        }) {
            return Err("mode_mismatch");
        }
        if !plan.resources.iter().any(|r| {
            r.provider == crate::descriptor::PROVIDER
                && r.resource_id == requested.identity
                && r.execution_domain == binding.execution_domain
                && r.access == ResourceAccess::Exclusive
        }) || !plan.mutation_domains.iter().any(|d| {
            d.domain == requested.domain_id
                && (!matches!(
                    request.phase,
                    LifecyclePhase::SessionPrepare | LifecyclePhase::StreamPrepare
                ) || d.expected_revision == requested.domain_revision)
                && d.access == ResourceAccess::Exclusive
        }) {
            return Err("virtual_target_not_admitted");
        }
        requested.reference().validate()?;
        if requested.provider_service != wire::SERVICE {
            return Err("invalid_virtual_service");
        }
        if !plan.obligations.iter().any(|o| {
            o.provider == crate::descriptor::PROVIDER
                && o.resource_id == requested.identity
                && o.cleanup_method.service == crate::descriptor::SERVICE
                && o.cleanup_method.method == "lifecycle_callback"
                && o.payload.get("service").and_then(Value::as_str) == Some(wire::SERVICE)
                && o.payload.get("identity").and_then(Value::as_str)
                    == Some(requested.identity.as_str())
                && o.payload.get("reference_id").and_then(Value::as_str)
                    == Some(requested.reference_id.as_str())
        }) {
            return Err("missing_cleanup_obligation");
        }
        let prepare = matches!(
            request.phase,
            LifecyclePhase::StreamPrepare | LifecyclePhase::SessionPrepare
        );
        if prepare && callback_parent.is_none() {
            return Err("missing_callback_parent");
        }
        if prepare && prior.is_some() {
            return Err("unexpected_prior_obligation");
        }
        if !prepare {
            let old = prior.ok_or("missing_prior_obligation")?;
            // The domain revision may have advanced when the borrow was made.
            requested.borrow = old.borrow.clone();
            if requested != old || old.reference_released {
                return Err("obligation_mismatch");
            }
            requested = old;
        }
        let fingerprint = serde_json::to_value(&request).map_err(|_| "invalid_request")?;
        if serde_json::to_vec(&fingerprint)
            .map_err(|_| "invalid_request")?
            .len()
            > 4096
        {
            return Err("receipt_request_too_large");
        }
        let deadline_ms = now_ms.saturating_add(request.remaining_ms.min(30_000));
        Ok(Self {
            sequence: request.provider_sequence,
            operation_id: request.operation_id.clone(),
            request,
            fingerprint,
            obligation: requested,
            phase: Phase::Reserve,
            call: None,
            status_count: 0,
            saved_borrow: false,
            result: None,
            deadline_ms,
            prepare,
            ready_output: None,
            callback_parent,
        })
    }
    /// One store or broker operation per tick; timeout preserves obligations.
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
        store: &mut impl DurableVirtualStore,
        guard: &mut impl EffectGuard,
    ) -> CallbackProgress {
        if self.phase != Phase::Done && now_ms >= self.deadline_ms {
            return self.unknown();
        }
        match self.phase {
            Phase::Reserve => match store.poll(&StoreCommand::Reserve {
                sequence: self.sequence,
                operation_id: self.operation_id.clone(),
                request: self.fingerprint.clone(),
            }) {
                StoreProgress::Waiting => CallbackProgress::Waiting,
                StoreProgress::Reserved => {
                    self.phase = if self.prepare {
                        Phase::SaveInitial
                    } else {
                        Phase::VerifyPrior
                    };
                    CallbackProgress::Waiting
                }
                StoreProgress::ExistingComplete(result) => {
                    if matches!(result, CallbackResult::Prepared { .. }) {
                        return self.unknown();
                    }
                    self.phase = Phase::Done;
                    self.result = Some(result.clone());
                    CallbackProgress::Complete(result)
                }
                _ => self.unknown(),
            },
            Phase::VerifyPrior => match store.poll(&StoreCommand::VerifyPrior {
                obligation: self.obligation.clone(),
            }) {
                StoreProgress::Waiting => CallbackProgress::Waiting,
                StoreProgress::Verified => {
                    self.phase = if self.obligation.borrow.is_some() {
                        Phase::ReleaseBorrow
                    } else {
                        Phase::Remove
                    };
                    CallbackProgress::Waiting
                }
                _ => self.unknown(),
            },
            Phase::SaveInitial
            | Phase::SaveBorrow
            | Phase::SaveValidated
            | Phase::SaveBorrowReleased
            | Phase::SaveReleased => {
                match store.poll(&StoreCommand::Save {
                    sequence: self.sequence,
                    obligation: self.obligation.clone(),
                }) {
                    StoreProgress::Waiting => CallbackProgress::Waiting,
                    StoreProgress::Saved => {
                        if self.phase == Phase::SaveValidated {
                            return self.finish_candidate();
                        }
                        self.phase = match self.phase {
                            Phase::SaveInitial => Phase::Create,
                            Phase::SaveBorrow => {
                                self.saved_borrow = true;
                                Phase::Borrow
                            }
                            Phase::SaveBorrowReleased => Phase::Remove,
                            Phase::SaveReleased => {
                                self.result = Some(CallbackResult::Released);
                                Phase::Complete
                            }
                            _ => unreachable!(),
                        };
                        CallbackProgress::Waiting
                    }
                    _ => self.unknown(),
                }
            }
            Phase::Create
            | Phase::Status
            | Phase::Borrow
            | Phase::Validate
            | Phase::ReleaseBorrow
            | Phase::Remove
            | Phase::CleanupStatus => self.poll_wire(now_ms, send, guard),
            Phase::Complete => {
                let Some(result) = self.result.clone() else {
                    return self.unknown();
                };
                match store.poll(&StoreCommand::Complete {
                    sequence: self.sequence,
                    operation_id: self.operation_id.clone(),
                    result: result.clone(),
                }) {
                    StoreProgress::Waiting => CallbackProgress::Waiting,
                    StoreProgress::Completed => {
                        self.phase = Phase::Done;
                        CallbackProgress::Complete(result)
                    }
                    _ => self.unknown(),
                }
            }
            Phase::Done => self.result.clone().map_or(
                CallbackProgress::RecoveryRequired,
                CallbackProgress::Complete,
            ),
        }
    }
    fn poll_wire(
        &mut self,
        now: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
        guard: &mut impl EffectGuard,
    ) -> CallbackProgress {
        let mutating = match self.phase {
            Phase::Create => Some(EffectKind::Create),
            Phase::Borrow => Some(EffectKind::Borrow),
            _ => None,
        };
        if let Some(effect) = mutating
            && self
                .call
                .as_ref()
                .is_none_or(|call| call.request_id().is_none())
        {
            let Some(parent) = self.callback_parent else {
                return self.unknown();
            };
            match guard.poll(&self.request, effect, parent, now, send) {
                GuardProgress::Waiting => return CallbackProgress::Waiting,
                GuardProgress::Authorized => {}
                GuardProgress::Rejected | GuardProgress::Unknown => return self.unknown(),
            }
        }
        if self.call.is_none() {
            let reference = self.obligation.reference();
            let request = match self.phase {
                Phase::Create => DisplayRequest::CreatePlanned {
                    create: self.obligation.create(),
                    layout: self.obligation.layout.clone(),
                    domain_id: self.obligation.domain_id.clone(),
                    revision: self.obligation.domain_revision,
                },
                Phase::Status | Phase::CleanupStatus => {
                    if self.status_count >= MAX_STATUS {
                        return self.unknown();
                    }
                    self.status_count += 1;
                    DisplayRequest::Status(reference)
                }
                Phase::Borrow => DisplayRequest::Borrow(reference),
                Phase::Validate => {
                    let Some(borrow) = &self.obligation.borrow else {
                        return self.unknown();
                    };
                    DisplayRequest::ValidateBorrow {
                        reference,
                        borrow_id: borrow.borrow_id.clone(),
                    }
                }
                Phase::ReleaseBorrow => {
                    let Some(borrow) = &self.obligation.borrow else {
                        return self.unknown();
                    };
                    DisplayRequest::ReleaseBorrow {
                        reference,
                        borrow_id: borrow.borrow_id.clone(),
                    }
                }
                Phase::Remove => DisplayRequest::Remove(reference),
                _ => unreachable!(),
            };
            let name = format!(
                "virtual.{}.{}.{}",
                self.operation_id,
                self.phase_name(),
                self.status_count
            );
            let Ok(call) = wire::PendingCall::new(
                request,
                name,
                mutating.and(self.callback_parent),
                self.deadline_ms.saturating_sub(now).min(30_000),
                now,
            ) else {
                return self.unknown();
            };
            self.call = Some(call);
        }
        let call = self.call.as_mut().expect("call was initialized");
        let progress = call.poll(now, send);
        // The broker result is still held; save a newly acquired borrow before
        // calling poll again, which would release that result.
        if self.phase == Phase::Borrow
            && !self.saved_borrow
            && let Some(DisplayOutcome::Borrowed(borrow)) = call.tentative()
        {
            self.obligation.borrow = Some(borrow.clone());
            self.phase = Phase::SaveBorrow;
            return CallbackProgress::Waiting;
        }
        match progress {
            CallProgress::Waiting => CallbackProgress::Waiting,
            CallProgress::Complete(outcome) => {
                self.call = None;
                self.accept(outcome)
            }
            CallProgress::Rejected(reason) if self.phase == Phase::Create => {
                self.result = Some(CallbackResult::Rejected { reason });
                self.phase = Phase::Complete;
                CallbackProgress::Waiting
            }
            _ => self.unknown(),
        }
    }
    fn accept(&mut self, outcome: DisplayOutcome) -> CallbackProgress {
        match (self.phase, outcome) {
            (Phase::Create, DisplayOutcome::Creating)
            | (Phase::Status, DisplayOutcome::Creating) => self.phase = Phase::Status,
            (Phase::Create, DisplayOutcome::Ready(ready))
            | (Phase::Status, DisplayOutcome::Ready(ready))
                if ready.active && ready.capture_output.is_some() =>
            {
                let Some(output) = ready.capture_output else {
                    return self.unknown();
                };
                if output != format!("kwin:{}", ready.device_path) {
                    return self.unknown();
                }
                self.ready_output = Some(output);
                self.phase = Phase::Borrow
            }
            (Phase::Borrow, DisplayOutcome::Borrowed(_)) if self.saved_borrow => {
                self.phase = Phase::Validate
            }
            (Phase::Validate, DisplayOutcome::Borrowed(current)) => {
                let Some(saved) = &self.obligation.borrow else {
                    return self.unknown();
                };
                if current.borrow_id != saved.borrow_id
                    || current.observed_output != saved.observed_output
                    || current.mutation_domain.id != self.obligation.domain_id
                    || current.mutation_domain.revision < saved.mutation_domain.revision
                    || current.mutation_domain.borrowers == 0
                    || current.mutation_domain.pending_mutations != 0
                    || current.observed_output.width != self.obligation.width
                    || current.observed_output.height != self.obligation.height
                    || current.observed_output.refresh_millihz != self.obligation.refresh_millihz
                    || self.ready_output.as_deref()
                        != Some(format!("kwin:{}", current.observed_output.output_name).as_str())
                {
                    return self.unknown();
                }
                self.obligation.borrow = Some(current);
                self.phase = Phase::SaveValidated;
            }
            (Phase::ReleaseBorrow, DisplayOutcome::BorrowReleased(domain))
                if domain.id == self.obligation.domain_id =>
            {
                self.obligation.borrow = None;
                self.phase = Phase::SaveBorrowReleased;
            }
            (Phase::Remove, DisplayOutcome::Removed | DisplayOutcome::ReferenceReleased) => {
                self.obligation.reference_released = true;
                self.phase = Phase::SaveReleased;
            }
            (Phase::Remove, DisplayOutcome::CleanupPending) => {
                self.status_count = 0;
                self.phase = Phase::CleanupStatus;
            }
            (
                Phase::CleanupStatus,
                DisplayOutcome::ReferenceAbsent {
                    monitor_present: false,
                },
            ) => {
                self.obligation.reference_released = true;
                self.phase = Phase::SaveReleased;
            }
            (
                Phase::CleanupStatus,
                DisplayOutcome::ReferenceAbsent {
                    monitor_present: true,
                },
            ) => self.phase = Phase::CleanupStatus,
            _ => return self.unknown(),
        }
        CallbackProgress::Waiting
    }
    fn finish_candidate(&mut self) -> CallbackProgress {
        let Some(candidate) =
            self.candidate(self.obligation.borrow.as_ref().expect("validated borrow"))
        else {
            return self.unknown();
        };
        let obligations: Vec<_> = self
            .request
            .approved_plan
            .as_ref()
            .expect("validated plan")
            .obligations
            .iter()
            .filter(|o| {
                o.provider == crate::descriptor::PROVIDER
                    && o.resource_id == self.obligation.identity
                    && o.cleanup_method.service == crate::descriptor::SERVICE
                    && o.cleanup_method.method == "lifecycle_callback"
                    && o.payload.get("service").and_then(Value::as_str) == Some(wire::SERVICE)
                    && o.payload.get("identity").and_then(Value::as_str)
                        == Some(self.obligation.identity.as_str())
                    && o.payload.get("reference_id").and_then(Value::as_str)
                        == Some(self.obligation.reference_id.as_str())
            })
            .cloned()
            .collect();
        if extension_api::validate_provider_response(
            &self.request,
            &ProviderResponse::Prepared {
                candidate: Some(candidate.clone()),
                obligations: obligations.clone(),
            },
        )
        .is_err()
        {
            return self.unknown();
        }
        self.result = Some(CallbackResult::Prepared {
            candidate: Box::new(candidate),
            obligations,
        });
        self.phase = Phase::Complete;
        CallbackProgress::Waiting
    }
    fn candidate(&self, borrow: &DisplayBorrow) -> Option<CaptureBinding> {
        let constraint = self
            .request
            .approved_plan
            .as_ref()?
            .candidate_constraint
            .as_ref()?;
        let mode = extension_api::VideoMode {
            width: self.obligation.width,
            height: self.obligation.height,
            refresh_millihz: self.obligation.refresh_millihz,
            hdr: false,
        };
        let resource = ResourceRef {
            provider: crate::descriptor::PROVIDER.into(),
            resource_id: self.obligation.identity.clone(),
            incarnation: producer_incarnation(
                &self.obligation.domain_id,
                &self.obligation.identity,
                &borrow.observed_output,
            ),
            revision: borrow.mutation_domain.revision,
            execution_domain: constraint.execution_domain.clone(),
            mutation_domain: Some(borrow.mutation_domain.id.clone()),
            mutation_domains: vec![borrow.mutation_domain.id.clone()],
        };
        Some(CaptureBinding {
            capture_provider: CAPTURE.into(),
            selector_schema: SELECTOR.into(),
            selector: json!({"output":format!("kwin:{}",borrow.observed_output.output_name)}),
            resource,
            mode,
            plan_revision: constraint.plan_revision,
            geometry_revision: self.obligation.geometry_revision,
            generation: match self.request.target {
                LifecycleTarget::Session { generation, .. }
                | LifecycleTarget::Stream { generation, .. }
                | LifecycleTarget::Validation { generation, .. } => generation,
            },
            fallback: CaptureFallback::Forbidden,
        })
    }
    fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::Create => "create",
            Phase::Status => "status",
            Phase::Borrow => "borrow",
            Phase::Validate => "validate",
            Phase::ReleaseBorrow => "release-borrow",
            Phase::Remove => "remove",
            Phase::CleanupStatus => "cleanup-status",
            _ => "invalid",
        }
    }
    fn unknown(&mut self) -> CallbackProgress {
        self.result = None;
        self.phase = Phase::Done;
        CallbackProgress::RecoveryRequired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    const ID: &str = "9c1d707f-7229-4fc4-b6e2-91f80c626a09";
    const DOMAIN: &str = "provider_session:abcdef";
    fn request() -> ProviderRequest {
        serde_json::from_value(json!({"provider_sequence":1,"operation":"lifecycle_callback","version":1,"transition_id":"transition-1","operation_id":"virtual-1","target":{"kind":"stream","host_epoch":"epoch-1","session_id":"session-1","stream_id":"stream-1","generation":7},"phase":"stream.prepare","settings_revision":"settings-1","settings":{},"intent":"initial","reason":null,"requested_video":null,"consumer_requirements":{"execution_domain":"desktop","capture_providers":[CAPTURE],"selector_schemas":[SELECTOR]},"remaining_ms":5000,"plan_revision":1,"admission_id":"admission-1","approved_plan":{"plan_id":"plan-1","revision":1,"resources":[{"provider":crate::descriptor::PROVIDER,"resource_id":ID,"incarnation":null,"expected_revision":null,"execution_domain":"desktop","mutation_domains":[DOMAIN],"access":"exclusive"}],"mutation_domains":[{"domain":DOMAIN,"expected_revision":1,"borrowers":{},"access":"exclusive"}],"required_capabilities":[],"constraints":{"virtual_display":{"provider_service":wire::SERVICE,"identity":ID,"reference_id":"stream-1","width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false,"scale":null,"layout":"extended","domain_id":DOMAIN,"domain_revision":1,"geometry_revision":3,"borrow":null,"reference_released":false}},"obligations":[{"obligation_id":"cleanup-1","provider":"nonary.display-settings","resource_id":ID,"mutation_domain":DOMAIN,"depends_on":[],"cleanup_method":{"service":"nonary.display-settings/1","method":"lifecycle_callback","interface_major":1,"interface_minor":0,"schema_revision":1},"payload":{"service":wire::SERVICE,"identity":ID,"reference_id":"stream-1"}}],"affected_consumers":[],"consumer_change":"reconnect_required","candidate_constraint":{"capture_provider":CAPTURE,"selector_schema":SELECTOR,"resource_provider":crate::descriptor::PROVIDER,"resource_id":ID,"incarnation":null,"execution_domain":"desktop","mode":{"width":1920,"height":1080,"refresh_millihz":60000,"hdr":false},"plan_revision":1},"allowed_degradation":[]}})).unwrap()
    }
    fn domain() -> Value {
        json!({"id":DOMAIN,"revision":2,"borrowers":1,"pending_mutations":0,"scope":"provider_session"})
    }
    fn borrow() -> Value {
        json!({"ok":true,"borrow_id":"a".repeat(64),"observed_output":{"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1920,"height":1080,"refresh_millihz":60000},"mutation_domain":domain()})
    }
    fn ready() -> Value {
        json!({"ok":true,"reference_owned":true,"monitor":{"specification":{"identity":ID,"width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false},"virtual_display_layout":"extended","dd_virtual_display_scale":0,"state":"ready","error":null,"ready":{"device_path":"Virtual-1","active":true},"capture_output":"kwin:Virtual-1"}})
    }
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
    struct DenyGuard;
    impl EffectGuard for DenyGuard {
        fn poll(
            &mut self,
            _: &ProviderRequest,
            _: EffectKind,
            _: u64,
            _: u64,
            _: &mut impl FnMut(Command) -> ModuleResult<Response>,
        ) -> GuardProgress {
            GuardProgress::Rejected
        }
    }
    struct FakeStore {
        replies: VecDeque<StoreProgress>,
        commands: Vec<StoreCommand>,
    }
    impl DurableVirtualStore for FakeStore {
        fn poll(&mut self, c: &StoreCommand) -> StoreProgress {
            self.commands.push(c.clone());
            self.replies.pop_front().unwrap()
        }
    }
    #[test]
    fn candidate_requires_saved_borrow_and_exact_provider_validation() {
        let mut machine =
            VirtualCallback::new(COORDINATOR, request(), None, |_| true, 0, Some(99)).unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([
                StoreProgress::Reserved,
                StoreProgress::Saved,
                StoreProgress::Waiting,
                StoreProgress::Saved,
                StoreProgress::Saved,
                StoreProgress::Completed,
            ]),
            commands: vec![],
        };
        let mut next_id = 0u64;
        let mut payload = Value::Null;
        let mut calls = Vec::new();
        let mut guard = AllowGuard;
        let mut send = |command: Command| {
            calls.push(command.clone());
            match command {
                Command::Request { payload: p, .. } => {
                    next_id += 1;
                    payload = match p["action"].as_str().unwrap() {
                        "create" => ready(),
                        "borrow" => borrow(),
                        "validate_borrow" => {
                            let mut value = borrow();
                            value["mutation_domain"]["revision"] = json!(3);
                            value["mutation_domain"]["borrowers"] = json!(2);
                            value
                        }
                        other => panic!("{other}"),
                    };
                    Ok(Response::Accepted { id: next_id })
                }
                Command::TakeResult { .. } => Ok(Response::Result {
                    payload: payload.clone(),
                }),
                Command::ReleaseResult { .. } => Ok(Response::Ok),
                _ => panic!("unexpected"),
            }
        };
        let mut result = CallbackProgress::Waiting;
        for tick in 1..50 {
            result = machine.poll(tick, &mut send, &mut store, &mut guard);
            if !matches!(result, CallbackProgress::Waiting) {
                break;
            }
        }
        let CallbackProgress::Complete(CallbackResult::Prepared { candidate, .. }) = result else {
            panic!("{result:?}")
        };
        let observed = serde_json::from_value(borrow()["observed_output"].clone()).unwrap();
        assert_eq!(
            candidate.resource.incarnation,
            producer_incarnation(DOMAIN, ID, &observed)
        );
        assert_eq!(candidate.resource.provider, crate::descriptor::PROVIDER);
        assert_eq!(candidate.resource.revision, 3);
        assert_eq!(candidate.selector["output"], "kwin:Virtual-1");
        assert_eq!(candidate.generation, 7);
        assert_eq!(candidate.geometry_revision, 3);
        assert!(
            matches!(&store.commands[2],StoreCommand::Save {obligation,..} if obligation.borrow.is_some())
        );
        let borrow_take = calls
            .iter()
            .position(|c| matches!(c, Command::TakeResult { request: 2 }))
            .unwrap();
        let borrow_release = calls
            .iter()
            .position(|c| matches!(c, Command::ReleaseResult { request: 2 }))
            .unwrap();
        assert!(borrow_take < borrow_release);
    }
    #[test]
    fn pending_receipt_and_wrong_admission_never_dispatch() {
        assert!(VirtualCallback::new("other", request(), None, |_| true, 0, Some(99)).is_err());
        let mut lower_service = request();
        lower_service.approved_plan.as_mut().unwrap().resources[0].provider = wire::SERVICE.into();
        assert!(
            VirtualCallback::new(COORDINATOR, lower_service, None, |_| true, 0, Some(99)).is_err()
        );
        let mut machine =
            VirtualCallback::new(COORDINATOR, request(), None, |_| true, 0, Some(99)).unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([StoreProgress::ExistingPending]),
            commands: vec![],
        };
        let mut guard = AllowGuard;
        let mut send = |_: Command| panic!("no provider call permitted");
        assert_eq!(
            machine.poll(1, &mut send, &mut store, &mut guard),
            CallbackProgress::RecoveryRequired
        );
    }
    #[test]
    fn stale_prepare_is_fenced_after_durable_wait() {
        let mut machine =
            VirtualCallback::new(COORDINATOR, request(), None, |_| true, 0, Some(99)).unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([StoreProgress::Reserved, StoreProgress::Saved]),
            commands: vec![],
        };
        let mut guard = DenyGuard;
        let mut send = |_: Command| panic!("stale effect must not dispatch");
        assert_eq!(
            machine.poll(1, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            machine.poll(2, &mut send, &mut store, &mut guard),
            CallbackProgress::Waiting
        );
        assert_eq!(
            machine.poll(3, &mut send, &mut store, &mut guard),
            CallbackProgress::RecoveryRequired
        );
    }
    #[test]
    fn acquired_borrow_persistence_failure_does_not_release_broker_result() {
        let mut machine =
            VirtualCallback::new(COORDINATOR, request(), None, |_| true, 0, Some(99)).unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([
                StoreProgress::Reserved,
                StoreProgress::Saved,
                StoreProgress::Unknown,
            ]),
            commands: vec![],
        };
        let mut next_id = 0;
        let mut payload = Value::Null;
        let mut calls = Vec::new();
        let mut guard = AllowGuard;
        let mut send = |command: Command| {
            calls.push(command.clone());
            match command {
                Command::Request { payload: p, .. } => {
                    next_id += 1;
                    payload = if p["action"] == "create" {
                        ready()
                    } else {
                        borrow()
                    };
                    Ok(Response::Accepted { id: next_id })
                }
                Command::TakeResult { .. } => Ok(Response::Result {
                    payload: payload.clone(),
                }),
                Command::ReleaseResult { .. } => Ok(Response::Ok),
                _ => panic!(),
            }
        };
        let mut result = CallbackProgress::Waiting;
        for tick in 1..30 {
            result = machine.poll(tick, &mut send, &mut store, &mut guard);
            if result != CallbackProgress::Waiting {
                break;
            }
        }
        assert_eq!(result, CallbackProgress::RecoveryRequired);
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, Command::ReleaseResult { request: 2 }))
        );
    }

    #[test]
    fn active_binding_validation_requires_live_matching_provider_borrow() {
        let machine =
            VirtualCallback::new(COORDINATOR, request(), None, |_| true, 0, Some(99)).unwrap();
        let borrow_payload = borrow();
        let owned = DisplayBorrow {
            borrow_id: borrow_payload["borrow_id"].as_str().unwrap().into(),
            observed_output: serde_json::from_value(borrow_payload["observed_output"].clone())
                .unwrap(),
            mutation_domain: serde_json::from_value(borrow_payload["mutation_domain"].clone())
                .unwrap(),
        };
        let mut obligation = machine.obligation.clone();
        obligation.borrow = Some(owned.clone());
        let binding = machine.candidate(&owned).unwrap();
        let req = BindingValidationRequest {
            operation_id: "validation-1".into(),
            transition_id: "transition-1".into(),
            target: request().target,
            plan_revision: 1,
            binding,
            observation: owned.observed_output.clone(),
        };
        let mut invalid = req.clone();
        invalid.observation.registry_global += 1;
        assert!(
            BindingValidator::new(COORDINATOR, invalid, obligation.clone(), |_| true, 100, 0)
                .is_err()
        );
        let mut validator =
            BindingValidator::new(COORDINATOR, req, obligation, |_| true, 100, 0).unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([StoreProgress::Verified]),
            commands: vec![],
        };
        let mut responses = VecDeque::from([
            Ok(Response::Accepted { id: 1 }),
            Ok(Response::Result { payload: borrow() }),
            Ok(Response::Ok),
        ]);
        let mut send = |_: Command| responses.pop_front().unwrap();
        assert!(validator.poll(1, &mut send, &mut store).is_none());
        assert!(validator.poll(2, &mut send, &mut store).is_none());
        assert!(validator.poll(3, &mut send, &mut store).is_none());
        assert!(matches!(
            validator.poll(4, &mut send, &mut store),
            Some(BindingValidationResult::Succeeded { .. })
        ));
    }

    #[test]
    fn producer_incarnation_is_shared_between_borrows_and_changes_with_output() {
        let payload = borrow();
        let first: DisplayBorrow = serde_json::from_value(json!({"borrow_id":payload["borrow_id"],"observed_output":payload["observed_output"],"mutation_domain":payload["mutation_domain"]})).unwrap();
        let mut second = first.clone();
        second.borrow_id = "c".repeat(64);
        second.mutation_domain.revision += 1;
        assert_eq!(
            producer_incarnation(DOMAIN, ID, &first.observed_output),
            producer_incarnation(DOMAIN, ID, &second.observed_output)
        );
        second.observed_output.width = 1280;
        second.observed_output.height = 720;
        assert_eq!(
            producer_incarnation(DOMAIN, ID, &first.observed_output),
            producer_incarnation(DOMAIN, ID, &second.observed_output)
        );
        second.observed_output.registry_global += 1;
        assert_ne!(
            producer_incarnation(DOMAIN, ID, &first.observed_output),
            producer_incarnation(DOMAIN, ID, &second.observed_output)
        );
    }
    #[test]
    fn release_verifies_ownership_then_releases_borrow_before_monitor() {
        let mut req = request();
        let mut prior = VirtualCallback::new(COORDINATOR, req.clone(), None, |_| true, 0, Some(99))
            .unwrap()
            .obligation;
        let p = borrow();
        prior.borrow = Some(DisplayBorrow {
            borrow_id: p["borrow_id"].as_str().unwrap().into(),
            observed_output: serde_json::from_value(p["observed_output"].clone()).unwrap(),
            mutation_domain: serde_json::from_value(p["mutation_domain"].clone()).unwrap(),
        });
        req.phase = LifecyclePhase::StreamRelease;
        // Acquiring the retained borrow advanced the domain after prepare.
        req.approved_plan.as_mut().unwrap().mutation_domains[0].expected_revision = 2;
        let mut machine =
            VirtualCallback::new(COORDINATOR, req, Some(prior), |_| true, 0, Some(99)).unwrap();
        let mut store = FakeStore {
            replies: VecDeque::from([
                StoreProgress::Reserved,
                StoreProgress::Verified,
                StoreProgress::Saved,
                StoreProgress::Saved,
                StoreProgress::Completed,
            ]),
            commands: vec![],
        };
        let mut current = Value::Null;
        let mut id = 0;
        let mut actions = Vec::new();
        let mut guard = AllowGuard;
        let mut send = |cmd: Command| match cmd {
            Command::Request { payload, .. } => {
                id += 1;
                let action = payload["action"].as_str().unwrap().to_owned();
                actions.push(action.clone());
                current = match action.as_str() {
                    "release_borrow" => {
                        json!({"ok":true,"released":true,"mutation_domain":domain()})
                    }
                    "remove" => json!({"ok":true,"removed":true,"identity":ID}),
                    _ => panic!(),
                };
                Ok(Response::Accepted { id })
            }
            Command::TakeResult { .. } => Ok(Response::Result {
                payload: current.clone(),
            }),
            Command::ReleaseResult { .. } => Ok(Response::Ok),
            _ => panic!(),
        };
        let mut result = CallbackProgress::Waiting;
        for tick in 1..40 {
            result = machine.poll(tick, &mut send, &mut store, &mut guard);
            if result != CallbackProgress::Waiting {
                break;
            }
        }
        assert_eq!(result, CallbackProgress::Complete(CallbackResult::Released));
        assert_eq!(actions, ["release_borrow", "remove"]);
        assert!(matches!(
            &store.commands[1],
            StoreCommand::VerifyPrior { .. }
        ));
        assert!(
            matches!(&store.commands[2],StoreCommand::Save {obligation,..} if obligation.borrow.is_none() && !obligation.reference_released)
        );
    }
}

/// Live validation is a bounded snapshot, not per-frame revocation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingValidationRequest {
    pub operation_id: String,
    pub transition_id: String,
    pub target: LifecycleTarget,
    pub plan_revision: u64,
    pub binding: CaptureBinding,
    pub observation: wire::ObservedOutput,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BindingValidationResult {
    Succeeded {
        operation_id: String,
        target: LifecycleTarget,
        plan_revision: u64,
        binding: Box<CaptureBinding>,
        observation: Box<wire::ObservedOutput>,
    },
    RecoveryRequired,
}
pub struct BindingValidator {
    request: BindingValidationRequest,
    obligation: VirtualObligation,
    verified: bool,
    call: wire::PendingCall,
    deadline_ms: u64,
    done: Option<BindingValidationResult>,
}
impl BindingValidator {
    /// `verify` authenticates the coordinator, current transition/target and
    /// binding against its admitted active plan. `obligation` must be loaded
    /// from the ownership journal; VerifyPrior rechecks it before provider use.
    pub fn new(
        caller: &str,
        request: BindingValidationRequest,
        obligation: VirtualObligation,
        verify: impl FnOnce(&BindingValidationRequest) -> bool,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        if caller != COORDINATOR
            || !verify(&request)
            || request.operation_id.is_empty()
            || request.transition_id.is_empty()
            || request.plan_revision == 0
            || request.binding.plan_revision != request.plan_revision
            || extension_api::validate_capture_binding(&request.binding).is_err()
        {
            return Err("invalid_validation_admission");
        }
        let borrow = obligation.borrow.as_ref().ok_or("missing_borrow")?;
        if obligation.provider_service != wire::SERVICE
            || obligation.reference_released
            || request.binding.resource.provider != crate::descriptor::PROVIDER
            || request.binding.resource.resource_id != obligation.identity
            || request.binding.resource.incarnation
                != producer_incarnation(
                    &obligation.domain_id,
                    &obligation.identity,
                    &borrow.observed_output,
                )
            || request.binding.capture_provider != CAPTURE
            || request.binding.selector_schema != SELECTOR
            || request.binding.selector
                != json!({"output":format!("kwin:{}",borrow.observed_output.output_name)})
            || request.observation != borrow.observed_output
            || request.binding.mode.width != obligation.width
            || request.binding.mode.height != obligation.height
            || request.binding.mode.refresh_millihz != obligation.refresh_millihz
            || request.binding.mode.hdr != obligation.hdr_enabled
        {
            return Err("binding_mismatch");
        }
        let call = wire::PendingCall::new(
            DisplayRequest::ValidateBorrow {
                reference: obligation.reference(),
                borrow_id: borrow.borrow_id.clone(),
            },
            format!("binding-validate.{}", request.operation_id),
            None,
            timeout_ms,
            now_ms,
        )?;
        Ok(Self {
            request,
            obligation,
            verified: false,
            call,
            deadline_ms: now_ms.saturating_add(timeout_ms),
            done: None,
        })
    }
    /// None means waiting; only Succeeded authorizes continued consumer use.
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
        store: &mut impl DurableVirtualStore,
    ) -> Option<BindingValidationResult> {
        if let Some(done) = &self.done {
            return Some(done.clone());
        }
        if now_ms >= self.deadline_ms {
            self.done = Some(BindingValidationResult::RecoveryRequired);
            return self.done.clone();
        }
        if !self.verified {
            return match store.poll(&StoreCommand::VerifyPrior {
                obligation: self.obligation.clone(),
            }) {
                StoreProgress::Waiting => None,
                StoreProgress::Verified => {
                    self.verified = true;
                    None
                }
                _ => {
                    self.done = Some(BindingValidationResult::RecoveryRequired);
                    self.done.clone()
                }
            };
        }
        match self.call.poll(now_ms, send) {
            CallProgress::Waiting => None,
            CallProgress::Complete(DisplayOutcome::Borrowed(current))
                if self.obligation.borrow.as_ref().is_some_and(|old| {
                    old.borrow_id == current.borrow_id
                        && old.observed_output == current.observed_output
                        && old.mutation_domain.id == current.mutation_domain.id
                        && current.mutation_domain.revision >= old.mutation_domain.revision
                }) && current.mutation_domain.pending_mutations == 0
                    && current.mutation_domain.borrowers > 0
                    && current.observed_output == self.request.observation =>
            {
                self.done = Some(BindingValidationResult::Succeeded {
                    operation_id: self.request.operation_id.clone(),
                    target: self.request.target.clone(),
                    plan_revision: self.request.plan_revision,
                    binding: Box::new(self.request.binding.clone()),
                    observation: Box::new(self.request.observation.clone()),
                });
                self.done.clone()
            }
            _ => {
                self.done = Some(BindingValidationResult::RecoveryRequired);
                self.done.clone()
            }
        }
    }
}
