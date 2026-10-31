//! Guarded virtual-display action execution using the public broker services.
//!
//! The caller must first reserve a durable action receipt and obtain the
//! coordinator's one-use `verify_action_effect` claim. Every native mutation is
//! preceded by a fresh `check_action_effect` against the held transition. The
//! coordinator must fence this reservation before retiring it; an absent guard
//! endpoint fails closed. No request field by itself establishes authority.
use crate::{
    action_provider::{self, EffectBackend, EffectProgress, ExecuteRequest},
    actions::{self, DisplayAction},
    descriptor,
    virtual_callback::VirtualObligation,
    virtual_display::{
        self, CallProgress, DisplayOutcome, DisplayReference, DisplayRequest, PendingCall,
    },
};
use amaterasu_module_sdk::{Command, ModuleResult, Response};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const STATE: &str = "amaterasu.state/1";
const LIFECYCLE: &str = "amaterasu.session-lifecycle/1";
const MAX_FAILURES: u8 = 3;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Load,
    CheckParent,
    Guard,
    Effect,
    SaveRead,
    SaveWrite,
    Done,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    ReleaseBorrow,
    Remove,
    CleanupStatus,
}
struct Exchange {
    command: Command,
    id: Option<u64>,
    reply: Option<Value>,
    uncertain: bool,
    failures: u8,
}

/// A bounded single-operation backend. The key must be resolved from the
/// coordinator-authenticated target, never copied from client arguments.
pub struct VirtualActionBackend {
    request: ExecuteRequest,
    key: String,
    parent: u64,
    deadline_ms: u64,
    stage: Stage,
    effect: Effect,
    exchange: Option<Exchange>,
    call: Option<PendingCall>,
    saved: Option<VirtualObligation>,
    next: Option<VirtualObligation>,
    expected_revision: Option<u64>,
    counter: u64,
    nonce: String,
    result: Option<EffectProgress>,
    armed: bool,
    resume_after_save: Stage,
    cleanup_attempts: u8,
}
impl VirtualActionBackend {
    pub fn new(
        caller: &str,
        request: ExecuteRequest,
        target_key: String,
        parent: u64,
        timeout_ms: u64,
        now_ms: u64,
        verify_target: impl FnOnce(&ExecuteRequest, &str) -> bool,
    ) -> Result<Self, &'static str> {
        if caller != action_provider::ACTION_CALLER
            || parent == 0
            || !(1..=30_000).contains(&timeout_ms)
            || target_key.is_empty()
            || target_key.len() > 160
            || target_key.chars().any(char::is_control)
            || !verify_target(&request, &target_key)
            || action_provider::plan_digest(&request.plan).ok().as_deref()
                != Some(request.plan_digest.as_str())
            || request.plan.resources.len() != 1
            || request.plan.mutation_domains.len() != 1
            || request.plan.obligations.is_empty()
            || actions::parse_action(&request.action_id, request.arguments.clone()).is_err()
            || request.plan.constraints.get("action")
                != Some(
                    &json!({"operation_id":request.operation_id,"action_id":request.action_id,"target":request.target,"arguments":request.arguments,"expected_settings_revision":request.expected_settings_revision}),
                )
        {
            return Err("invalid_or_unauthorized_action");
        }
        let action = actions::parse_action(&request.action_id, request.arguments.clone())
            .map_err(|_| "invalid_action")?;
        if let DisplayAction::SetMode(mode) = action {
            let numerator = u64::from(mode.refresh.numerator) * 1000;
            let denominator = u64::from(mode.refresh.denominator);
            if denominator == 0
                || numerator % denominator != 0
                || !(320..=7680).contains(&mode.resolution.width)
                || !(200..=4320).contains(&mode.resolution.height)
                || u32::try_from(numerator / denominator)
                    .map_or(true, |rate| !(1000..=1_000_000).contains(&rate))
            {
                return Err("unsupported_mode");
            }
        }
        let hash = format!("{:x}", Sha256::digest(request.operation_id.as_bytes()));
        let key = format!("virtual-obligation/v1/{target_key}");
        let exchange = make_exchange(
            STATE,
            json!({"action":"get","key":key}),
            format!("action.{}.load", &hash[..32]),
            parent,
            timeout_ms,
        );
        // The coordinator currently cannot allocate a replacement binding's
        // geometry revision. Never infer that authority from a provider plan.
        let unsupported_replacement = matches!(
            action,
            DisplayAction::RecreateOwned | DisplayAction::SetMode(_)
        );
        Ok(Self {
            request,
            key,
            parent,
            deadline_ms: now_ms.saturating_add(timeout_ms),
            stage: if unsupported_replacement {
                Stage::Done
            } else {
                Stage::Load
            },
            effect: Effect::Remove,
            exchange: Some(exchange),
            call: None,
            saved: None,
            next: None,
            expected_revision: None,
            counter: 0,
            nonce: String::new(),
            result: unsupported_replacement.then(|| {
                EffectProgress::FailedClean(
                    json!({"reason":"replacement_geometry_authority_unavailable"}),
                )
            }),
            armed: false,
            resume_after_save: Stage::Effect,
            cleanup_attempts: 0,
        })
    }
    /// Drive one broker command. A native result is journaled before its broker
    /// acknowledgement is released; uncertain operations remain recoverable.
    pub fn advance(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) {
        if !self.armed {
            return;
        }
        if self.stage == Stage::Done {
            return;
        }
        if now_ms >= self.deadline_ms {
            self.unknown();
            return;
        }
        if self.stage == Stage::CheckParent {
            if !matches!(
                send(Command::CheckRequest {
                    request: self.parent
                }),
                Ok(Response::Ok)
            ) {
                self.unknown();
                return;
            }
            self.counter = match self.counter.checked_add(1) {
                Some(v) => v,
                None => {
                    self.unknown();
                    return;
                }
            };
            self.nonce = format!("guard-{}-{}", self.short_id(), self.counter);
            let payload = json!({"operation":"check_action_effect","operation_id":self.request.operation_id,"action_id":self.request.action_id,"target":self.request.target,"plan_digest":self.request.plan_digest,"permit":self.request.permit,"provider":descriptor::PROVIDER,"execute_method":method(),"guard_nonce":self.nonce});
            self.exchange = Some(make_exchange(
                LIFECYCLE,
                payload,
                format!("action.{}.guard.{}", self.short_id(), self.counter),
                self.parent,
                self.remaining(now_ms),
            ));
            self.stage = Stage::Guard;
            return;
        }
        if self.stage == Stage::Effect {
            self.drive_effect(now_ms, send);
            return;
        }
        let Some(exchange) = self.exchange.as_mut() else {
            self.unknown();
            return;
        };
        let Some(result) = poll_exchange(exchange, now_ms, send) else {
            return;
        };
        let Ok(payload) = result else {
            self.unknown();
            return;
        };
        self.exchange = None;
        match self.stage {
            Stage::Load => self.loaded(payload),
            Stage::Guard => self.guarded(payload, now_ms),
            Stage::SaveRead => self.save_read(payload, now_ms),
            Stage::SaveWrite => self.save_write(payload),
            _ => self.unknown(),
        }
    }
    fn loaded(&mut self, payload: Value) {
        let Some(value) = payload.get("value") else {
            self.unknown();
            return;
        };
        let Ok(obligation) = serde_json::from_value::<VirtualObligation>(value.clone()) else {
            self.unknown();
            return;
        };
        if payload.get("ok").and_then(Value::as_bool) != Some(true)
            || payload.get("found").and_then(Value::as_bool) != Some(true)
            || !matches_owned_plan(&self.request, &obligation)
        {
            self.unknown();
            return;
        }
        self.effect = if obligation.borrow.is_some() {
            Effect::ReleaseBorrow
        } else {
            Effect::Remove
        };
        self.saved = Some(obligation);
        self.stage = Stage::CheckParent;
    }
    fn guarded(&mut self, payload: Value, now_ms: u64) {
        if payload.get("status").and_then(Value::as_str) != Some("succeeded")
            || payload.get("guard_nonce").and_then(Value::as_str) != Some(self.nonce.as_str())
            || payload.get("operation_id").and_then(Value::as_str)
                != Some(self.request.operation_id.as_str())
            || payload.get("action_id").and_then(Value::as_str)
                != Some(self.request.action_id.as_str())
            || payload.get("target") != Some(&json!(self.request.target))
            || payload.get("plan_digest").and_then(Value::as_str)
                != Some(self.request.plan_digest.as_str())
            || payload.get("provider").and_then(Value::as_str) != Some(descriptor::PROVIDER)
            || payload.get("execute_method") != Some(&method())
        {
            self.unknown();
            return;
        }
        let Some(saved) = &self.saved else {
            self.unknown();
            return;
        };
        let reference = DisplayReference {
            identity: saved.identity.clone(),
            reference_id: saved.reference_id.clone(),
        };
        let operation = match self.effect {
            Effect::ReleaseBorrow => {
                let Some(borrow) = &saved.borrow else {
                    self.unknown();
                    return;
                };
                DisplayRequest::ReleaseBorrow {
                    reference,
                    borrow_id: borrow.borrow_id.clone(),
                }
            }
            Effect::Remove => DisplayRequest::Remove(reference),
            Effect::CleanupStatus => DisplayRequest::Status(reference),
        };
        let label = match self.effect {
            Effect::ReleaseBorrow => "release-borrow",
            Effect::Remove => "remove",
            Effect::CleanupStatus => "cleanup-status",
        };
        match PendingCall::new(
            operation,
            format!(
                "action.{}.{}.{}",
                self.short_id(),
                label,
                self.cleanup_attempts
            ),
            Some(self.parent),
            self.remaining(now_ms),
            now_ms,
        ) {
            Ok(call) => {
                self.call = Some(call);
                self.stage = Stage::Effect
            }
            Err(_) => self.unknown(),
        }
    }
    fn drive_effect(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) {
        let Some(call) = self.call.as_mut() else {
            self.unknown();
            return;
        };
        let progress = call.poll(now_ms, send);
        let mut changed = None;
        if let Some(outcome) = call.tentative() {
            let Some(saved) = &self.saved else {
                self.unknown();
                return;
            };
            let mut next = saved.clone();
            match (self.effect, outcome) {
                (Effect::ReleaseBorrow, DisplayOutcome::BorrowReleased(domain))
                    if domain.id == saved.domain_id =>
                {
                    next.borrow = None;
                    changed = Some(next);
                }
                (Effect::Remove, DisplayOutcome::Removed | DisplayOutcome::ReferenceReleased) => {
                    next.reference_released = true;
                    changed = Some(next);
                }
                (
                    Effect::CleanupStatus,
                    DisplayOutcome::ReferenceAbsent {
                        monitor_present: false,
                    },
                ) => {
                    next.reference_released = true;
                    changed = Some(next);
                }
                _ => {}
            }
        }
        if let Some(next) = changed
            && self.next.as_ref() != Some(&next)
            && self.saved.as_ref() != Some(&next)
        {
            self.next = Some(next);
            self.resume_after_save = Stage::Effect;
            self.start_save_read(now_ms);
            return;
        }
        match progress {
            CallProgress::Waiting => {}
            CallProgress::Complete(DisplayOutcome::BorrowReleased(_))
                if self.effect == Effect::ReleaseBorrow
                    && self.saved.as_ref().is_some_and(|s| s.borrow.is_none()) =>
            {
                self.call = None;
                self.next = None;
                self.effect = Effect::Remove;
                self.stage = Stage::CheckParent;
            }
            CallProgress::Complete(DisplayOutcome::Removed | DisplayOutcome::ReferenceReleased)
                if self.effect == Effect::Remove
                    && self.saved.as_ref().is_some_and(|s| s.reference_released) =>
            {
                self.call = None;
                self.next = None;
                let saved = self.saved.as_ref().unwrap();
                self.result = Some(EffectProgress::Succeeded(
                    json!({"identity":saved.identity,"reference_id":saved.reference_id,"reference_released":true}),
                ));
                self.stage = Stage::Done;
            }
            CallProgress::Complete(DisplayOutcome::CleanupPending)
                if self.effect == Effect::Remove =>
            {
                self.call = None;
                self.next = None;
                self.cleanup_attempts = 1;
                self.effect = Effect::CleanupStatus;
                self.stage = Stage::CheckParent;
            }
            CallProgress::Complete(DisplayOutcome::ReferenceAbsent {
                monitor_present: false,
            }) if self.effect == Effect::CleanupStatus
                && self.saved.as_ref().is_some_and(|s| s.reference_released) =>
            {
                let saved = self.saved.as_ref().unwrap();
                self.result = Some(EffectProgress::Succeeded(
                    json!({"identity":saved.identity,"reference_id":saved.reference_id,"reference_released":true}),
                ));
                self.stage = Stage::Done;
            }
            CallProgress::Complete(DisplayOutcome::ReferenceAbsent {
                monitor_present: true,
            }) if self.effect == Effect::CleanupStatus => {
                self.call = None;
                self.cleanup_attempts = match self.cleanup_attempts.checked_add(1) {
                    Some(value) if value <= 16 => value,
                    _ => {
                        self.unknown();
                        return;
                    }
                };
                self.stage = Stage::CheckParent;
            }

            _ => self.unknown(),
        }
    }
    fn start_save_read(&mut self, now_ms: u64) {
        self.counter += 1;
        self.exchange = Some(make_exchange(
            STATE,
            json!({"action":"get","key":self.key}),
            format!("action.{}.save-read.{}", self.short_id(), self.counter),
            self.parent,
            self.remaining(now_ms),
        ));
        self.stage = Stage::SaveRead;
    }
    fn save_read(&mut self, payload: Value, now_ms: u64) {
        let current = payload
            .get("value")
            .cloned()
            .and_then(|v| serde_json::from_value::<VirtualObligation>(v).ok());
        let revision = payload.get("revision").and_then(Value::as_u64);
        if payload.get("ok").and_then(Value::as_bool) != Some(true)
            || payload.get("found").and_then(Value::as_bool) != Some(true)
            || current.as_ref() != self.saved.as_ref()
        {
            self.unknown();
            return;
        }
        let Some(revision) = revision else {
            self.unknown();
            return;
        };
        let Some(next_revision) = revision.checked_add(1) else {
            self.unknown();
            return;
        };
        self.expected_revision = Some(next_revision);
        self.counter += 1;
        self.exchange = Some(make_exchange(
            STATE,
            json!({"action":"set","key":self.key,"value":self.next,"expected_revision":revision}),
            format!("action.{}.save-write.{}", self.short_id(), self.counter),
            self.parent,
            self.remaining(now_ms),
        ));
        self.stage = Stage::SaveWrite;
    }
    fn save_write(&mut self, payload: Value) {
        if payload.get("ok").and_then(Value::as_bool) != Some(true)
            || payload.get("revision").and_then(Value::as_u64) != self.expected_revision
        {
            self.unknown();
            return;
        }
        self.saved = self.next.clone();
        self.stage = self.resume_after_save;
    }
    fn short_id(&self) -> String {
        format!("{:x}", Sha256::digest(self.request.operation_id.as_bytes()))[..24].into()
    }
    fn remaining(&self, now_ms: u64) -> u64 {
        self.deadline_ms.saturating_sub(now_ms).min(30_000)
    }
    fn unknown(&mut self) {
        self.result = Some(EffectProgress::Unknown);
        self.stage = Stage::Done;
    }
}
impl EffectBackend for VirtualActionBackend {
    fn poll(&mut self, request: &ExecuteRequest) -> EffectProgress {
        if request != &self.request {
            return EffectProgress::Unknown;
        }
        self.armed = true;
        self.result.clone().unwrap_or(EffectProgress::Waiting)
    }
}
fn method() -> Value {
    json!({"service":descriptor::SERVICE,"method":"action_execute","interface_major":1,"interface_minor":0,"schema_revision":1})
}
fn matches_owned_plan(request: &ExecuteRequest, obligation: &VirtualObligation) -> bool {
    let Some(resource) = request.plan.resources.first() else {
        return false;
    };
    let Some(domain) = request.plan.mutation_domains.first() else {
        return false;
    };
    let exact = request
        .plan
        .constraints
        .pointer("/provider/virtual")
        .cloned()
        .and_then(|v| serde_json::from_value::<VirtualObligation>(v).ok());
    let reference = DisplayReference {
        identity: obligation.identity.clone(),
        reference_id: obligation.reference_id.clone(),
    };
    let exact_borrow = obligation.borrow.as_ref().is_none_or(|borrow| {
        resource.incarnation.as_deref()
            == Some(
                crate::virtual_callback::producer_incarnation(
                    &obligation.domain_id,
                    &obligation.identity,
                    &borrow.observed_output,
                )
                .as_str(),
            )
            && domain.expected_revision == borrow.mutation_domain.revision
            && domain.domain == borrow.mutation_domain.id
            && borrow.mutation_domain.pending_mutations == 0
    });
    reference.validate().is_ok()
        && !obligation.reference_released
        && obligation.provider_service == virtual_display::SERVICE
        && exact.as_ref() == Some(obligation)
        && exact_borrow
        && resource.provider == descriptor::PROVIDER
        && resource.resource_id == obligation.identity
        && resource.access == amaterasu_module_sdk::extension_api::ResourceAccess::Exclusive
        && domain.domain == obligation.domain_id
        && domain.access == amaterasu_module_sdk::extension_api::ResourceAccess::Exclusive
        && resource.mutation_domains.contains(&domain.domain)
        && request.plan.obligations.iter().any(|o| {
            o.provider == descriptor::PROVIDER
                && o.resource_id == obligation.identity
                && o.payload.get("identity").and_then(Value::as_str)
                    == Some(obligation.identity.as_str())
                && o.payload.get("reference_id").and_then(Value::as_str)
                    == Some(obligation.reference_id.as_str())
                && o.payload.get("service").and_then(Value::as_str)
                    == Some(virtual_display::SERVICE)
        })
}
fn make_exchange(
    service: &str,
    payload: Value,
    operation_id: String,
    parent: u64,
    timeout_ms: u64,
) -> Exchange {
    Exchange {
        command: Command::Request {
            service: service.into(),
            payload,
            operation_id,
            parent: Some(parent),
            timeout_ms,
        },
        id: None,
        reply: None,
        uncertain: false,
        failures: 0,
    }
}
fn poll_exchange(
    exchange: &mut Exchange,
    _now_ms: u64,
    send: &mut impl FnMut(Command) -> ModuleResult<Response>,
) -> Option<Result<Value, ()>> {
    if exchange.failures >= MAX_FAILURES {
        return Some(Err(()));
    }
    if let Some(id) = exchange.id {
        if exchange.reply.is_some() {
            match send(Command::ReleaseResult { request: id }) {
                Ok(Response::Ok) => Some(Ok(exchange.reply.take().expect("reply"))),
                _ => {
                    exchange.failures += 1;
                    None
                }
            }
        } else {
            match send(Command::TakeResult { request: id }) {
                Ok(Response::Pending) => None,
                Ok(Response::Result { payload }) => {
                    exchange.reply = Some(payload);
                    None
                }
                _ => {
                    exchange.failures += 1;
                    None
                }
            }
        }
    } else {
        match send(exchange.command.clone()) {
            Ok(Response::Accepted { id }) => {
                exchange.id = Some(id);
                exchange.failures = 0;
                None
            }
            Ok(Response::Error { .. }) if !exchange.uncertain => Some(Err(())),
            _ => {
                exchange.uncertain = true;
                exchange.failures += 1;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_provider::{PlanRequest, TargetSnapshot};
    use std::collections::BTreeMap;
    fn obligation() -> VirtualObligation {
        serde_json::from_value(json!({"provider_service":virtual_display::SERVICE,"identity":"9c1d707f-7229-4fc4-b6e2-91f80c626a09","reference_id":"reference-1","width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false,"scale":0,"layout":"extended","domain_id":"provider_session:abc","domain_revision":2,"geometry_revision":3,"borrow":{"borrow_id":"a".repeat(64),"observed_output":{"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1920,"height":1080,"refresh_millihz":60000},"mutation_domain":{"id":"provider_session:abc","revision":2,"borrowers":1,"pending_mutations":0,"scope":"provider_session"}},"reference_released":false})).unwrap()
    }
    fn request() -> ExecuteRequest {
        let o = obligation();
        let target = json!({"kind":"stream","host_epoch":"epoch","session_id":"session","stream_id":"stream","expected_generation":1});
        let req:PlanRequest=serde_json::from_value(json!({"version":1,"operation_id":"epoch:1","action_id":actions::REMOVE_OWNED,"target":target,"arguments":{},"expected_settings_revision":"rev"})).unwrap();
        let snapshot=TargetSnapshot { resource:serde_json::from_value(json!({"provider":descriptor::PROVIDER,"resource_id":o.identity,"incarnation":crate::virtual_callback::producer_incarnation(&o.domain_id,&o.identity,&o.borrow.as_ref().unwrap().observed_output),"expected_revision":2,"execution_domain":"desktop","mutation_domains":[o.domain_id],"access":"exclusive"})).unwrap(),domain:serde_json::from_value(json!({"domain":o.domain_id,"expected_revision":2,"borrowers":{"stream":1},"access":"exclusive"})).unwrap(),obligations:vec![serde_json::from_value(json!({"obligation_id":"cleanup","provider":descriptor::PROVIDER,"resource_id":o.identity,"mutation_domain":o.domain_id,"depends_on":[],"cleanup_method":{"service":descriptor::SERVICE,"method":"lifecycle_callback","interface_major":1,"interface_minor":0,"schema_revision":1},"payload":{"service":virtual_display::SERVICE,"identity":o.identity,"reference_id":o.reference_id}})).unwrap()],affected_consumers:vec!["capture".into()],settings_revision:"rev".into(),provider_constraints:json!({"virtual":o}) };
        let plan =
            action_provider::plan(action_provider::ACTION_CALLER, &req, snapshot, |_, _| true)
                .unwrap();
        ExecuteRequest {
            version: 1,
            operation_id: req.operation_id,
            action_id: req.action_id,
            target: req.target,
            arguments: req.arguments,
            expected_settings_revision: req.expected_settings_revision,
            plan_digest: action_provider::plan_digest(&plan).unwrap(),
            plan,
            permit: "permit".into(),
        }
    }
    struct Broker {
        obligation: VirtualObligation,
        revision: u64,
        replies: BTreeMap<u64, Value>,
        next: u64,
        events: Vec<String>,
        guard_allowed: bool,
        deny_guard_at: Option<usize>,
        guard_count: usize,
        pending_remove: bool,
    }
    impl Broker {
        fn new() -> Self {
            Self {
                obligation: obligation(),
                revision: 0,
                replies: BTreeMap::new(),
                next: 0,
                events: vec![],
                guard_allowed: true,
                deny_guard_at: None,
                guard_count: 0,
                pending_remove: false,
            }
        }
        fn send(&mut self, command: Command) -> ModuleResult<Response> {
            match command {
                Command::CheckRequest { .. } => Ok(Response::Ok),
                Command::Request {
                    service, payload, ..
                } => {
                    let action = payload
                        .get("action")
                        .or_else(|| payload.get("operation"))
                        .and_then(Value::as_str)
                        .unwrap();
                    self.events.push(format!("{service}:{action}"));
                    let result = if service == STATE {
                        match action {
                            "get" => {
                                json!({"ok":true,"found":true,"revision":self.revision,"value":self.obligation})
                            }
                            "set"
                                if payload["expected_revision"].as_u64() == Some(self.revision) =>
                            {
                                self.obligation =
                                    serde_json::from_value(payload["value"].clone()).unwrap();
                                self.revision += 1;
                                json!({"ok":true,"revision":self.revision})
                            }
                            _ => json!({"ok":false}),
                        }
                    } else if service == LIFECYCLE {
                        self.guard_count += 1;
                        if self.guard_allowed && self.deny_guard_at != Some(self.guard_count) {
                            let mut value = payload.clone();
                            value["status"] = json!("succeeded");
                            value.as_object_mut().unwrap().remove("permit");
                            value
                        } else {
                            json!({"status":"rejected"})
                        }
                    } else if service == virtual_display::SERVICE {
                        match action {
                            "release_borrow" => {
                                json!({"ok":true,"released":true,"mutation_domain":{"id":"provider_session:abc","revision":3,"borrowers":0,"pending_mutations":0,"scope":"provider_session"}})
                            }
                            "remove" => {
                                if self.pending_remove {
                                    json!({"ok":true,"removed":false,"reference_owned":false,"monitor":{"specification":{"identity":self.obligation.identity},"state":"removing"}})
                                } else {
                                    json!({"ok":true,"removed":true,"identity":self.obligation.identity})
                                }
                            }
                            "status" => {
                                json!({"ok":true,"enabled":true,"native_supported":true,"recovery_ready":true,"reference_owned":false,"monitors":[],"mutation_domain":{"id":"provider_session:abc","revision":4,"borrowers":0,"pending_mutations":0,"scope":"provider_session"}})
                            }
                            "create" => {
                                json!({"ok":true,"reference_owned":true,"monitor":{"specification":{"identity":self.obligation.identity,"width":self.obligation.width,"height":self.obligation.height,"refresh_millihz":self.obligation.refresh_millihz,"name":self.obligation.name,"hdr_enabled":false},"virtual_display_layout":"extended","dd_virtual_display_scale":0,"state":"ready","error":null,"ready":{"device_path":"Virtual-1","active":true},"capture_output":"kwin:Virtual-1"}})
                            }
                            "borrow" | "validate_borrow" => {
                                json!({"ok":true,"borrow_id":"a".repeat(64),"observed_output":{"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":self.obligation.width,"height":self.obligation.height,"refresh_millihz":self.obligation.refresh_millihz},"mutation_domain":{"id":"provider_session:abc","revision":6,"borrowers":1,"pending_mutations":0,"scope":"provider_session"}})
                            }
                            _ => panic!("unexpected native action"),
                        }
                    } else {
                        panic!("unexpected service")
                    };
                    self.next += 1;
                    self.replies.insert(self.next, result);
                    Ok(Response::Accepted { id: self.next })
                }
                Command::TakeResult { request } => Ok(Response::Result {
                    payload: self.replies[&request].clone(),
                }),
                Command::ReleaseResult { request } => {
                    self.replies.remove(&request);
                    Ok(Response::Ok)
                }
                _ => panic!("unexpected command"),
            }
        }
    }
    #[test]
    fn guarded_remove_durably_saves_borrow_and_reference_retirement() {
        let req = request();
        let mut broker = Broker::new();
        let mut backend = VirtualActionBackend::new(
            action_provider::ACTION_CALLER,
            req.clone(),
            "session".into(),
            99,
            5000,
            0,
            |_, _| true,
        )
        .unwrap();
        backend.advance(0, &mut |c| broker.send(c));
        assert!(broker.events.is_empty());
        assert_eq!(backend.poll(&req), EffectProgress::Waiting);
        let mut outcome = EffectProgress::Waiting;
        for tick in 1..200 {
            backend.advance(tick, &mut |c| broker.send(c));
            outcome = backend.poll(&req);
            if outcome != EffectProgress::Waiting {
                break;
            }
        }
        assert!(
            matches!(outcome, EffectProgress::Succeeded(_)),
            "{outcome:?}"
        );
        assert!(broker.obligation.reference_released);
        assert!(broker.obligation.borrow.is_none());
        let guards = broker
            .events
            .iter()
            .filter(|event| event.ends_with(":check_action_effect"))
            .count();
        assert_eq!(guards, 2);
        let native: Vec<_> = broker
            .events
            .iter()
            .filter(|event| event.starts_with(virtual_display::SERVICE))
            .cloned()
            .collect();
        assert_eq!(
            native,
            vec![
                format!("{}:release_borrow", virtual_display::SERVICE),
                format!("{}:remove", virtual_display::SERVICE)
            ]
        );
    }
    #[test]
    fn guard_or_target_failure_never_dispatches_native_effect() {
        let req = request();
        let mut broker = Broker::new();
        broker.guard_allowed = false;
        let mut backend = VirtualActionBackend::new(
            action_provider::ACTION_CALLER,
            req.clone(),
            "session".into(),
            99,
            5000,
            0,
            |_, _| true,
        )
        .unwrap();
        assert_eq!(backend.poll(&req), EffectProgress::Waiting);
        for tick in 0..50 {
            backend.advance(tick, &mut |c| broker.send(c));
            if backend.poll(&req) != EffectProgress::Waiting {
                break;
            }
        }
        assert_eq!(backend.poll(&req), EffectProgress::Unknown);
        assert!(
            !broker
                .events
                .iter()
                .any(|e| e.starts_with(virtual_display::SERVICE))
        );
        assert!(
            VirtualActionBackend::new("foreign", req, "session".into(), 99, 1000, 0, |_, _| true)
                .is_err()
        );
    }
    #[test]
    fn replacement_without_coordinator_geometry_is_rejected_before_effect() {
        for (action, args) in [
            (actions::RECREATE_OWNED, json!({})),
            (
                actions::SET_MODE,
                json!({"width":1280,"height":720,"refresh_numerator":60,"refresh_denominator":1}),
            ),
        ] {
            let mut req = request();
            req.action_id = action.into();
            req.arguments = args;
            req.plan.constraints["action"]["action_id"] = json!(req.action_id);
            req.plan.constraints["action"]["arguments"] = req.arguments.clone();
            req.plan_digest = action_provider::plan_digest(&req.plan).unwrap();
            let mut broker = Broker::new();
            let mut backend = VirtualActionBackend::new(
                action_provider::ACTION_CALLER,
                req.clone(),
                "session".into(),
                99,
                5000,
                0,
                |_, _| true,
            )
            .unwrap();
            assert!(
                matches!(backend.poll(&req), EffectProgress::FailedClean(receipt) if receipt["reason"] == "replacement_geometry_authority_unavailable")
            );
            backend.advance(1, &mut |c| broker.send(c));
            assert!(broker.events.is_empty());
        }
    }
    #[test]
    fn revoked_guard_after_borrow_release_stops_before_monitor_removal() {
        let req = request();
        let mut broker = Broker::new();
        broker.deny_guard_at = Some(2);
        let mut backend = VirtualActionBackend::new(
            action_provider::ACTION_CALLER,
            req.clone(),
            "session".into(),
            99,
            5000,
            0,
            |_, _| true,
        )
        .unwrap();
        assert_eq!(backend.poll(&req), EffectProgress::Waiting);
        for tick in 1..200 {
            backend.advance(tick, &mut |c| broker.send(c));
            if backend.poll(&req) != EffectProgress::Waiting {
                break;
            }
        }
        assert_eq!(backend.poll(&req), EffectProgress::Unknown);
        assert!(broker.obligation.borrow.is_none());
        assert!(!broker.obligation.reference_released);
        assert!(
            !broker
                .events
                .iter()
                .any(|event| event == &format!("{}:remove", virtual_display::SERVICE))
        );
    }
    #[test]
    fn pending_native_cleanup_is_polled_until_absence_before_reporting_success() {
        let req = request();
        let mut broker = Broker::new();
        broker.pending_remove = true;
        let mut backend = VirtualActionBackend::new(
            action_provider::ACTION_CALLER,
            req.clone(),
            "session".into(),
            99,
            5000,
            0,
            |_, _| true,
        )
        .unwrap();
        assert_eq!(backend.poll(&req), EffectProgress::Waiting);
        let mut outcome = EffectProgress::Waiting;
        for tick in 1..200 {
            backend.advance(tick, &mut |c| broker.send(c));
            outcome = backend.poll(&req);
            if outcome != EffectProgress::Waiting {
                break;
            }
        }
        assert!(
            matches!(outcome, EffectProgress::Succeeded(_)),
            "{outcome:?}"
        );
        assert!(broker.obligation.reference_released);
        assert_eq!(
            broker
                .events
                .iter()
                .filter(|event| event.ends_with(":remove"))
                .count(),
            1
        );
        assert_eq!(
            broker
                .events
                .iter()
                .filter(|event| event.ends_with(":status"))
                .count(),
            1
        );
    }
}
