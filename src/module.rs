//! Native extension API entry point. Lifecycle effects stay closed until the
//! coordinator can prove the complete admitted request and retirement fence.
use crate::coordinator::{PendingVerification, Verification};
use amaterasu_module_sdk::{
    ApiFieldKind as Kind, ApiMethod, ApiPrivilege, ApiSchema, Command, ManagedModule, ModuleResult,
    Response, RuntimeClient,
    extension_api::{
        self, LifecyclePhase, LifecycleTarget, ProviderOperation, ProviderRequest,
        ProviderStatusRequest,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Instant};

const SERVICE: &str = "nonary.display-settings/1";
const REGISTRY_CALLER: &str = "amaterasu.extension-registry";
const LIFECYCLE_CALLER: &str = "amaterasu.session-lifecycle";
const MAX_PENDING: usize = 32;
const REGISTERED_METHODS: &[&str] = &[
    "settings_validate",
    "resource_plan",
    "lifecycle_callback",
    "lifecycle_status",
    "binding_validate",
    "action_plan",
    "action_execute",
    "action_status",
];

pub struct DisplaySettingsModule {
    runtime: RuntimeClient,
    clock: Instant,
    pending: Vec<PendingRequest>,
}
struct PendingRequest {
    request_id: u64,
    phase: PendingPhase,
}
enum PendingPhase {
    ActionPlan {
        planner: Box<crate::action_provider::ActionPlanner>,
        request: Box<crate::action_provider::PlanRequest>,
    },
    ActionExecute {
        machine: Box<crate::action_provider::ActionExecution>,
        store: Box<crate::action_store::DurableActionStore>,
        backend: Box<crate::action_backend::VirtualActionBackend>,
        operation_id: String,
    },
    ActionStatus {
        request: Box<crate::action_provider::StatusRequest>,
        store: Box<crate::action_store::DurableActionStore>,
    },
    Plan {
        planner: Box<crate::resource_plan::Planner>,
    },
    PhysicalReleaseLoad {
        request: Box<ProviderRequest>,
        domains: Vec<extension_api::MutationDomainPlan>,
        plans: Vec<extension_api::ResourcePlan>,
        obligations: Vec<extension_api::ResourceObligation>,
        store: Box<crate::durable_store::StateDurableStore>,
    },
    PhysicalReleasePlan {
        planner: Box<crate::physical_release_plan::PhysicalReleasePlanner>,
        domain: extension_api::MutationDomainPlan,
        obligations: Vec<extension_api::ResourceObligation>,
    },
    RefreshRelease {
        request: Box<ProviderRequest>,
        refresh: Box<crate::observation_refresh::ObservationRefresh>,
        plans: Vec<extension_api::ResourcePlan>,
        obligations: Vec<extension_api::ResourceObligation>,
    },
    PlanReleaseLoad {
        request: Box<ProviderRequest>,
        expected: Box<crate::virtual_callback::VirtualObligation>,
        domains: Vec<extension_api::MutationDomainPlan>,
        plans: Vec<extension_api::ResourcePlan>,
        obligations: Vec<extension_api::ResourceObligation>,
        store: Box<crate::durable_store::VirtualDurableStateStore>,
    },
    PlanSessionLoad {
        planner: Box<crate::resource_plan::Planner>,
        target: LifecycleTarget,
        store: Box<crate::durable_store::VirtualDurableStateStore>,
    },
    StatusLookup {
        status: Box<ProviderStatusRequest>,
        lookup: Box<crate::durable_store::PriorReceiptLookup>,
    },
    StatusVerify {
        request: Box<ProviderRequest>,
        receipt: Box<crate::receipt_store::Receipt>,
        verification: Box<PendingVerification>,
    },
    StatusBindingLoad {
        request: Box<ProviderRequest>,
        candidate: Box<extension_api::CaptureBinding>,
        obligations: Vec<extension_api::ResourceObligation>,
        store: Box<crate::durable_store::VirtualDurableStateStore>,
    },
    StatusBinding {
        validator: Box<crate::virtual_callback::BindingValidator>,
        store: Box<crate::durable_store::VirtualDurableStateStore>,
        candidate: Box<extension_api::CaptureBinding>,
        obligations: Vec<extension_api::ResourceObligation>,
    },
    Verify {
        request: Box<ProviderRequest>,
        verification: Box<PendingVerification>,
    },
    PhysicalLoad {
        request: Box<ProviderRequest>,
        store: Box<crate::durable_store::StateDurableStore>,
    },
    VirtualLoad {
        request: Box<ProviderRequest>,
        store: Box<crate::durable_store::VirtualDurableStateStore>,
    },
    Physical {
        machine: Box<crate::physical_callback::PhysicalCallback>,
        store: Box<crate::durable_store::StateDurableStore>,
        obligations: Vec<extension_api::ResourceObligation>,
        guard: Box<LiveEffectGuard>,
    },
    BindingLoad {
        request: Box<crate::virtual_callback::BindingValidationRequest>,
        store: Box<crate::durable_store::VirtualDurableStateStore>,
        timeout_ms: u64,
    },
    Binding {
        validator: Box<crate::virtual_callback::BindingValidator>,
        store: Box<crate::durable_store::VirtualDurableStateStore>,
    },
    Virtual {
        machine: Box<crate::virtual_callback::VirtualCallback>,
        store: Box<crate::durable_store::VirtualDurableStateStore>,
        obligations: Vec<extension_api::ResourceObligation>,
        guard: Box<LiveEffectGuard>,
    },
}
fn schema(required: &[(&str, Kind)], optional: &[(&str, Kind)]) -> ApiSchema {
    ApiSchema {
        required: required
            .iter()
            .cloned()
            .map(|(k, v)| (k.into(), v))
            .collect(),
        optional: optional
            .iter()
            .cloned()
            .map(|(k, v)| (k.into(), v))
            .collect::<BTreeMap<_, _>>(),
        allow_extra: false,
    }
}
fn registration(method: &str) -> Command {
    let provider_fields = [
        ("provider_sequence", Kind::Integer),
        ("operation", Kind::String),
        ("version", Kind::Integer),
        ("transition_id", Kind::String),
        ("operation_id", Kind::String),
        ("target", Kind::Object),
        ("phase", Kind::String),
        ("settings_revision", Kind::String),
        ("settings", Kind::Object),
        ("intent", Kind::Any),
        ("reason", Kind::Any),
        ("requested_video", Kind::Any),
        ("consumer_requirements", Kind::Object),
        ("remaining_ms", Kind::Integer),
        ("plan_revision", Kind::Any),
        ("admission_id", Kind::Any),
        ("approved_plan", Kind::Any),
    ];
    let request = match method {
        "settings_validate" => schema(&[("values", Kind::Object)], &[]),
        "resource_plan" | "lifecycle_callback" => schema(&provider_fields, &[]),
        "lifecycle_status" => schema(
            &[
                ("provider_sequence", Kind::Integer),
                ("operation_id", Kind::String),
                ("transition_id", Kind::String),
                ("receipt_id", Kind::String),
            ],
            &[],
        ),
        "binding_validate" => schema(
            &[
                ("operation_id", Kind::String),
                ("transition_id", Kind::String),
                ("target", Kind::Object),
                ("plan_revision", Kind::Integer),
                ("binding", Kind::Object),
                ("observation", Kind::Object),
            ],
            &[],
        ),
        "action_plan" => schema(
            &[
                ("version", Kind::Integer),
                ("operation_id", Kind::String),
                ("action_id", Kind::String),
                ("target", Kind::Object),
                ("arguments", Kind::Object),
                ("expected_settings_revision", Kind::Any),
            ],
            &[],
        ),
        "action_execute" => schema(
            &[
                ("version", Kind::Integer),
                ("operation_id", Kind::String),
                ("action_id", Kind::String),
                ("target", Kind::Object),
                ("arguments", Kind::Object),
                ("expected_settings_revision", Kind::Any),
                ("plan", Kind::Object),
                ("plan_digest", Kind::String),
                ("permit", Kind::String),
            ],
            &[],
        ),
        "action_status" => schema(
            &[
                ("version", Kind::Integer),
                ("operation_id", Kind::String),
                ("action_id", Kind::String),
                ("target", Kind::Object),
                ("plan_digest", Kind::String),
                ("provider_receipt", Kind::Object),
            ],
            &[],
        ),
        _ => unreachable!("known registered method"),
    };
    let response = if method == "settings_validate" {
        schema(
            &[("ok", Kind::Boolean), ("valid", Kind::Boolean)],
            &[("message", Kind::String)],
        )
    } else {
        schema(
            &[("status", Kind::String)],
            &[
                ("reason", Kind::String),
                ("receipt_id", Kind::String),
                ("plan", Kind::Object),
                ("candidate", Kind::Any),
                ("obligations", Kind::Array),
                ("outcomes", Kind::Array),
                ("operation_id", Kind::String),
                ("target", Kind::Object),
                ("plan_revision", Kind::Integer),
                ("binding", Kind::Object),
                ("observation", Kind::Object),
                ("action_id", Kind::String),
                ("receipt", Kind::Object),
                ("cleanup_complete", Kind::Boolean),
            ],
        )
    };
    Command::RegisterApi {
        method: ApiMethod {
            service: SERVICE.into(),
            method: method.into(),
            interface_major: 1,
            interface_minor: 0,
            request,
            response,
            privilege: ApiPrivilege::User,
        },
    }
}
fn arguments(payload: &Value) -> Option<(&str, &Value)> {
    let object = payload.as_object()?;
    if object.len() != 4
        || object.get("interface_major")?.as_u64()? != 1
        || object.get("interface_minor")?.as_u64()? != 0
    {
        return None;
    }
    Some((object.get("method")?.as_str()?, object.get("arguments")?))
}
fn validate_request(caller: &str, payload: Value) -> Value {
    if caller != REGISTRY_CALLER {
        return json!({"ok":true,"valid":false,"message":"unauthorized caller"});
    }
    let Some(("settings_validate", arguments)) = arguments(&payload) else {
        return json!({"ok":true,"valid":false,"message":"invalid request"});
    };
    let Some(object) = arguments.as_object().filter(|value| value.len() == 1) else {
        return json!({"ok":true,"valid":false,"message":"invalid request"});
    };
    let values = object
        .get("values")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
    match values.map(|values| crate::settings_schema::validate(&values)) {
        Some(Ok(())) => json!({"ok":true,"valid":true}),
        Some(Err(reason)) => {
            json!({"ok":true,"valid":false,"message":reason.chars().take(256).collect::<String>()})
        }
        None => json!({"ok":true,"valid":false,"message":"invalid settings"}),
    }
}
fn rejected(reason: &str) -> Value {
    json!({"status":"rejected","reason":reason})
}
fn recovery(reason: &str) -> Value {
    json!({"status":"recovery_required","reason":reason})
}
enum Dispatch {
    Immediate(Value),
    Verify(Box<ProviderRequest>, Box<PendingVerification>),
    Binding(Box<crate::virtual_callback::BindingValidationRequest>),
    Status(Box<ProviderStatusRequest>),
    ActionExecute(Box<crate::action_provider::ExecuteRequest>),
    ActionStatus(Box<crate::action_provider::StatusRequest>),
    ActionPlan(Box<crate::action_provider::PlanRequest>),
}
fn dispatch(caller: &str, payload: &Value, now_ms: u64, remaining_ms: u64) -> Dispatch {
    let Some((method, args)) = arguments(payload) else {
        return Dispatch::Immediate(rejected("invalid_request"));
    };
    if matches!(method, "action_plan" | "action_execute" | "action_status") {
        if caller != crate::action_provider::ACTION_CALLER || remaining_ms == 0 {
            return Dispatch::Immediate(rejected("unauthorized_caller"));
        }
        return match method {
            "action_execute" => serde_json::from_value(args.clone())
                .map(|r| Dispatch::ActionExecute(Box::new(r)))
                .unwrap_or_else(|_| Dispatch::Immediate(rejected("invalid_request"))),
            "action_status" => serde_json::from_value(args.clone())
                .map(|r| Dispatch::ActionStatus(Box::new(r)))
                .unwrap_or_else(|_| Dispatch::Immediate(rejected("invalid_request"))),
            _ => serde_json::from_value(args.clone())
                .map(|r| Dispatch::ActionPlan(Box::new(r)))
                .unwrap_or_else(|_| Dispatch::Immediate(rejected("invalid_request"))),
        };
    }
    if caller != LIFECYCLE_CALLER {
        return Dispatch::Immediate(rejected("unauthorized_caller"));
    }
    match method {
        "resource_plan" | "lifecycle_callback" => {
            let Ok(request) = serde_json::from_value::<ProviderRequest>(args.clone()) else {
                return Dispatch::Immediate(rejected("invalid_request"));
            };
            let expected = if method == "resource_plan" {
                ProviderOperation::ResourcePlan
            } else {
                ProviderOperation::LifecycleCallback
            };
            if request.operation != expected
                || extension_api::validate_provider_request(&request).is_err()
            {
                return Dispatch::Immediate(rejected("invalid_request"));
            }
            if remaining_ms == 0 {
                return Dispatch::Immediate(rejected("request_ended"));
            }
            match PendingVerification::from_request(caller, &request, now_ms) {
                Ok(verification) => Dispatch::Verify(Box::new(request), Box::new(verification)),
                Err(_) => Dispatch::Immediate(rejected("invalid_coordinator_admission")),
            }
        }
        "lifecycle_status" => match serde_json::from_value::<ProviderStatusRequest>(args.clone()) {
            Ok(status) if status.receipt_id == status.operation_id && remaining_ms > 0 => {
                Dispatch::Status(Box::new(status))
            }
            _ => Dispatch::Immediate(rejected("invalid_request")),
        },
        "binding_validate" => {
            match serde_json::from_value::<crate::virtual_callback::BindingValidationRequest>(
                args.clone(),
            ) {
                Ok(request) if remaining_ms > 0 => Dispatch::Binding(Box::new(request)),
                _ => Dispatch::Immediate(rejected("invalid_request")),
            }
        }
        _ => Dispatch::Immediate(rejected("unknown_method")),
    }
}
fn target_store_key(target: &LifecycleTarget) -> Result<String, &'static str> {
    let encoded = serde_json::to_vec(target).map_err(|_| "invalid_target")?;
    Ok(format!("target-{:x}", Sha256::digest(encoded)))
}
fn target_epoch(target: &LifecycleTarget) -> &str {
    match target {
        LifecycleTarget::Session { host_epoch, .. }
        | LifecycleTarget::Stream { host_epoch, .. }
        | LifecycleTarget::Validation { host_epoch, .. } => host_epoch,
    }
}

fn action_lifecycle_target(
    target: &extension_api::ActionTarget,
) -> Result<LifecycleTarget, &'static str> {
    match target {
        extension_api::ActionTarget::Session {
            host_epoch,
            session_id,
            expected_generation,
        } => Ok(LifecycleTarget::Session {
            host_epoch: host_epoch.clone(),
            session_id: session_id.clone(),
            generation: *expected_generation,
        }),
        extension_api::ActionTarget::Stream {
            host_epoch,
            session_id,
            stream_id,
            expected_generation,
        } => Ok(LifecycleTarget::Stream {
            host_epoch: host_epoch.clone(),
            session_id: session_id.clone(),
            stream_id: stream_id.clone(),
            generation: *expected_generation,
        }),
        extension_api::ActionTarget::Host { .. } => Err("unsupported_action_target"),
    }
}

fn start_action_execute(
    request: Box<crate::action_provider::ExecuteRequest>,
    parent: u64,
    now_ms: u64,
    remaining_ms: u64,
) -> Result<PendingPhase, &'static str> {
    let timeout = remaining_ms.min(30_000);
    let target: LifecycleTarget = serde_json::from_value(
        request
            .plan
            .constraints
            .pointer("/provider/lifecycle_target")
            .cloned()
            .ok_or("missing_action_target")?,
    )
    .map_err(|_| "invalid_action_target")?;
    let selected = match &target {
        LifecycleTarget::Stream {
            host_epoch,
            session_id,
            stream_id,
            generation,
        } => extension_api::ActionTarget::Stream {
            host_epoch: host_epoch.clone(),
            session_id: session_id.clone(),
            stream_id: stream_id.clone(),
            expected_generation: *generation,
        },
        _ => return Err("invalid_action_target"),
    };
    if action_lifecycle_target(&selected)? != target
        || !crate::action_provider::target_matches(&request.target, &selected, &target)
    {
        return Err("action_target_mismatch");
    }
    let key = target_store_key(&target)?;
    let backend = crate::action_backend::VirtualActionBackend::new(
        crate::action_provider::ACTION_CALLER,
        (*request).clone(),
        key,
        parent,
        timeout,
        now_ms,
        |_, _| true,
    )?;
    let store = crate::action_store::DurableActionStore::new(
        crate::action_provider::ACTION_CALLER,
        format!("action.{parent}"),
        Some(parent),
        timeout,
        |_| true,
    )?;
    let operation_id = request.operation_id.clone();
    let machine = crate::action_provider::ActionExecution::new(
        crate::action_provider::ACTION_CALLER,
        *request,
        now_ms,
        timeout,
    )?;
    Ok(PendingPhase::ActionExecute {
        machine: Box::new(machine),
        store: Box::new(store),
        backend: Box::new(backend),
        operation_id,
    })
}

fn action_recovery(operation_id: &str) -> Value {
    json!({"status":"recovery_required","receipt":{"operation_id":operation_id,"reason":"effect_unknown"}})
}
fn cleanup(obligations: &[extension_api::ResourceObligation]) -> Value {
    let outcomes: Vec<_> = obligations.iter().map(|obligation| json!({"obligation_id":obligation.obligation_id,"state":"released","reason":null})).collect();
    json!({"status":"cleanup","outcomes":outcomes})
}
fn admitted_obligations(
    request: &ProviderRequest,
) -> Result<Vec<extension_api::ResourceObligation>, &'static str> {
    let plan = request.approved_plan.as_ref().ok_or("missing_plan")?;
    if plan.obligations.is_empty() {
        return Err("missing_cleanup_obligation");
    }
    let virtual_constraint = plan.constraints.get("virtual_display");
    let physical_constraint = plan.constraints.get("physical");
    let valid = plan.obligations.iter().all(|obligation| {
        if obligation.provider != crate::descriptor::PROVIDER
            || obligation.cleanup_method.service != SERVICE
            || obligation.cleanup_method.method != "lifecycle_callback"
            || obligation.cleanup_method.interface_major != 1
            || obligation.cleanup_method.interface_minor != 0
        {
            return false;
        }
        if let Some(constraint) = virtual_constraint {
            return constraint.get("identity").and_then(Value::as_str)
                == Some(obligation.resource_id.as_str())
                && constraint.get("identity") == obligation.payload.get("identity")
                && constraint.get("reference_id") == obligation.payload.get("reference_id")
                && obligation.payload.get("service").and_then(Value::as_str)
                    == Some("amaterasu.virtual-display/1");
        }
        if let Some(constraint) = physical_constraint {
            return obligation.payload.get("service").and_then(Value::as_str)
                == Some("amaterasu.display/1")
                && constraint
                    .get("configuration")
                    .and_then(|v| v.get("displays"))
                    .and_then(Value::as_array)
                    .is_some_and(|displays| {
                        displays.iter().any(|display| {
                            display.get("id").and_then(Value::as_str)
                                == Some(obligation.resource_id.as_str())
                        })
                    });
        }
        false
    });
    if valid {
        Ok(plan.obligations.clone())
    } else {
        Err("unowned_cleanup_obligation")
    }
}
#[derive(Default)]
struct LiveEffectGuard {
    current: Option<(
        crate::virtual_callback::EffectKind,
        u64,
        PendingVerification,
    )>,
}
impl crate::virtual_callback::EffectGuard for LiveEffectGuard {
    fn poll(
        &mut self,
        request: &ProviderRequest,
        effect: crate::virtual_callback::EffectKind,
        parent: u64,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> crate::virtual_callback::GuardProgress {
        use crate::virtual_callback::GuardProgress;
        if self.current.is_none() {
            let Ok(verification) =
                PendingVerification::from_request(LIFECYCLE_CALLER, request, now_ms)
            else {
                return GuardProgress::Unknown;
            };
            self.current = Some((effect, parent, verification));
        }
        let (active_effect, active_parent, verification) =
            self.current.as_mut().expect("initialized");
        if *active_effect != effect || *active_parent != parent {
            self.current = None;
            return GuardProgress::Unknown;
        }
        match verification.poll(now_ms, send) {
            Verification::Pending => GuardProgress::Waiting,
            Verification::Rejected => {
                self.current = None;
                GuardProgress::Rejected
            }
            Verification::Unknown => {
                self.current = None;
                GuardProgress::Unknown
            }
            Verification::Verified => {
                self.current = None;
                if matches!(
                    send(Command::CheckRequest { request: parent }),
                    Ok(Response::Ok)
                ) {
                    GuardProgress::Authorized
                } else {
                    GuardProgress::Unknown
                }
            }
        }
    }
}
fn start_effect(request: Box<ProviderRequest>) -> Result<PendingPhase, &'static str> {
    use crate::durable_store::{StateDurableStore, VerifiedTarget, VirtualDurableStateStore};
    use crate::receipt_store::VerifiedEpoch;
    // This function is called only after full coordinator request verification.
    admitted_obligations(&request)?;
    let epoch = VerifiedEpoch::authenticate(target_epoch(&request.target).to_owned(), |_| true)?;
    let target = VerifiedTarget::authenticate(target_store_key(&request.target)?, |_| true)?;
    let prefix = format!("display.{}", request.provider_sequence);
    let timeout = request.remaining_ms.min(30_000);
    let constraints = &request
        .approved_plan
        .as_ref()
        .ok_or("missing_plan")?
        .constraints;
    let physical = constraints.get("physical").is_some();
    let virtual_display = constraints.get("virtual_display").is_some();
    match (physical, virtual_display) {
        (true, false) => {
            let mut store = StateDurableStore::new(epoch, target, prefix, None, timeout)?;
            store.start_load()?;
            Ok(PendingPhase::PhysicalLoad {
                request,
                store: Box::new(store),
            })
        }
        (false, true) => {
            let mut store = VirtualDurableStateStore::new(epoch, target, prefix, None, timeout)?;
            store.start_load()?;
            Ok(PendingPhase::VirtualLoad {
                request,
                store: Box::new(store),
            })
        }
        _ => Err("unsupported_or_ambiguous_plan"),
    }
}
fn start_binding(
    request: Box<crate::virtual_callback::BindingValidationRequest>,
    id: u64,
    timeout_ms: u64,
) -> Result<PendingPhase, &'static str> {
    use crate::durable_store::{VerifiedTarget, VirtualDurableStateStore};
    use crate::receipt_store::VerifiedEpoch;
    // The broker-authenticated lifecycle caller selects the exact target. The
    // store reads only that target; BindingValidator compares the saved borrow,
    // binding, mode, provider and independent observation before use.
    let epoch = VerifiedEpoch::authenticate(target_epoch(&request.target).to_owned(), |_| true)?;
    let target = VerifiedTarget::authenticate(target_store_key(&request.target)?, |_| true)?;
    let timeout_ms = timeout_ms.min(30_000);
    let mut store =
        VirtualDurableStateStore::new(epoch, target, format!("binding.{id}"), None, timeout_ms)?;
    store.start_load()?;
    Ok(PendingPhase::BindingLoad {
        request,
        store: Box::new(store),
        timeout_ms,
    })
}
fn receipt_response(request: &ProviderRequest, receipt: &crate::receipt_store::Receipt) -> Value {
    let crate::receipt_store::ReceiptState::Completed { result } = &receipt.state else {
        return recovery("pending_or_interrupted_effect");
    };
    let Some(plan) = request.approved_plan.as_ref() else {
        return recovery("missing_recorded_plan");
    };
    let Ok(obligations) = admitted_obligations(request) else {
        return recovery("unowned_cleanup_obligation");
    };
    if plan.constraints.get("virtual_display").is_some() {
        match serde_json::from_value::<crate::virtual_callback::CallbackResult>(result.clone()) {
            Ok(crate::virtual_callback::CallbackResult::Released) => cleanup(&obligations),
            Ok(crate::virtual_callback::CallbackResult::Rejected { reason }) => rejected(&reason),
            // A saved candidate does not establish that its borrow is still live.
            _ => recovery("binding_revalidation_required"),
        }
    } else if plan.constraints.get("physical").is_some() {
        match serde_json::from_value::<crate::physical_callback::CallbackResult>(result.clone()) {
            Ok(crate::physical_callback::CallbackResult::Restored { .. }) => cleanup(&obligations),
            Ok(crate::physical_callback::CallbackResult::Rejected { reason }) => rejected(&reason),
            _ => recovery("physical_revalidation_required"),
        }
    } else {
        recovery("unsupported_recorded_plan")
    }
}
fn prior_physical_cleanup(
    prior: &crate::physical_display::RecoveryObligation,
    plans: &[extension_api::ResourcePlan],
    obligations: &[extension_api::ResourceObligation],
) -> Result<
    (
        extension_api::ResourcePlan,
        Vec<extension_api::ResourceObligation>,
    ),
    &'static str,
> {
    let expected = json!({"provider": crate::physical_display::SERVICE,
        "configuration": prior.configuration, "expected_topology_revision": prior.topology_revision,
        "expected_mutation_domain_id": prior.mutation_domain_id,
        "expected_mutation_domain_revision": prior.mutation_domain_revision});
    let mut matching = plans
        .iter()
        .filter(|plan| plan.constraints.get("physical") == Some(&expected));
    let plan = matching.next().ok_or("release_prior_plan_unavailable")?;
    if matching.next().is_some() {
        return Err("release_prior_plan_ambiguous");
    }
    if plan.obligations.is_empty() || plan.obligations.iter().any(|o| !obligations.contains(o)) {
        return Err("release_prior_obligation_unavailable");
    }
    Ok((plan.clone(), plan.obligations.clone()))
}
fn prior_virtual_cleanup(
    prior: &crate::virtual_callback::VirtualObligation,
    plans: &[extension_api::ResourcePlan],
    obligations: &[extension_api::ResourceObligation],
) -> Result<extension_api::ResourceObligation, &'static str> {
    let mut expected = prior.clone();
    expected.borrow = None;
    let mut found = plans.iter().filter_map(|plan| {
        let constraint: crate::virtual_callback::VirtualObligation =
            serde_json::from_value(plan.constraints.get("virtual_display")?.clone()).ok()?;
        if constraint != expected {
            return None;
        }
        let mut matches = plan.obligations.iter().filter(|obligation| {
            obligation.provider == crate::descriptor::PROVIDER
                && obligation.resource_id == prior.identity
                && obligation.mutation_domain.as_deref() == Some(prior.domain_id.as_str())
                && obligation.cleanup_method.service == crate::descriptor::SERVICE
                && obligation.cleanup_method.method == "lifecycle_callback"
                && obligation.payload.get("service").and_then(Value::as_str)
                    == Some(crate::virtual_display::SERVICE)
                && obligation.payload.get("identity").and_then(Value::as_str)
                    == Some(prior.identity.as_str())
                && obligation
                    .payload
                    .get("reference_id")
                    .and_then(Value::as_str)
                    == Some(prior.reference_id.as_str())
                && obligations.contains(obligation)
        });
        let found = matches.next()?.clone();
        if matches.next().is_some() {
            return None;
        }
        Some(found)
    });
    let selected = found.next().ok_or("release_prior_plan_unavailable")?;
    if found.next().is_some() {
        return Err("release_prior_plan_ambiguous");
    }
    Ok(selected)
}
fn preparing(request: &ProviderRequest) -> bool {
    matches!(
        request.phase,
        LifecyclePhase::SessionPrepare | LifecyclePhase::StreamPrepare
    )
}
fn advance_phase(
    phase: PendingPhase,
    request_id: u64,
    now_ms: u64,
    send: &mut impl FnMut(Command) -> ModuleResult<Response>,
) -> Result<PendingPhase, Value> {
    use crate::durable_store::LoadProgress;
    match phase {
        PendingPhase::ActionPlan {
            mut planner,
            request,
        } => match planner.poll(now_ms, send) {
            crate::action_provider::ActionPlanProgress::Waiting => {
                Ok(PendingPhase::ActionPlan { planner, request })
            }
            crate::action_provider::ActionPlanProgress::Planned(plan) => Err(
                json!({"status":"planned","operation_id":request.operation_id,"action_id":request.action_id,"target":request.target,"plan":plan}),
            ),
            crate::action_provider::ActionPlanProgress::Rejected(reason) => Err(rejected(reason)),
            _ => Err(recovery("action_plan_unknown")),
        },
        PendingPhase::ActionExecute {
            mut machine,
            mut store,
            mut backend,
            operation_id,
        } => {
            store.advance(now_ms, send);
            backend.advance(now_ms, send);
            match machine.poll(now_ms, send, &mut *store, &mut *backend) {
                crate::action_provider::Progress::Waiting => Ok(PendingPhase::ActionExecute {
                    machine,
                    store,
                    backend,
                    operation_id,
                }),
                crate::action_provider::Progress::Complete(result) => {
                    Err(serde_json::to_value(result)
                        .unwrap_or_else(|_| action_recovery(&operation_id)))
                }
                _ => Err(action_recovery(&operation_id)),
            }
        }
        PendingPhase::ActionStatus { request, mut store } => {
            store.advance(now_ms, send);
            match crate::action_provider::status(
                crate::action_provider::ACTION_CALLER,
                &request,
                &mut *store,
            ) {
                crate::action_provider::Progress::Waiting => {
                    Ok(PendingPhase::ActionStatus { request, store })
                }
                crate::action_provider::Progress::Complete(result) => {
                    Err(serde_json::to_value(result)
                        .unwrap_or_else(|_| action_recovery(&request.operation_id)))
                }
                crate::action_provider::Progress::Rejected(reason) => Err(rejected(reason)),
                _ => Err(action_recovery(&request.operation_id)),
            }
        }
        PendingPhase::PhysicalReleaseLoad {
            request,
            domains,
            plans,
            obligations,
            mut store,
        } => {
            store.advance(now_ms, send);
            match store.poll_load() {
                LoadProgress::Waiting => Ok(PendingPhase::PhysicalReleaseLoad {
                    request,
                    domains,
                    plans,
                    obligations,
                    store,
                }),
                LoadProgress::Found(prior) => {
                    let (prior_plan, retained) =
                        prior_physical_cleanup(&prior, &plans, &obligations).map_err(recovery)?;
                    let mut matching = domains.into_iter().filter(|domain| {
                        Some(domain.domain.as_str()) == prior.mutation_domain_id.as_deref()
                    });
                    let domain = matching
                        .next()
                        .ok_or_else(|| recovery("release_domain_unavailable"))?;
                    if matching.next().is_some() {
                        return Err(recovery("ambiguous_release_domain"));
                    }
                    let planner = crate::physical_release_plan::PhysicalReleasePlanner::new(
                        LIFECYCLE_CALLER,
                        *request,
                        prior,
                        &prior_plan.mutation_domains,
                        Some(request_id),
                        now_ms,
                        |_, _| true,
                    )
                    .map_err(rejected)?;
                    Ok(PendingPhase::PhysicalReleasePlan {
                        planner: Box::new(planner),
                        domain,
                        obligations: retained,
                    })
                }
                LoadProgress::Absent => Err(recovery("release_ownership_unavailable")),
                LoadProgress::Unknown => Err(recovery("release_ownership_unknown")),
            }
        }
        PendingPhase::PhysicalReleasePlan {
            mut planner,
            domain,
            obligations,
        } => match planner.poll(now_ms, send) {
            crate::resource_plan::PlanProgress::Waiting => Ok(PendingPhase::PhysicalReleasePlan {
                planner,
                domain,
                obligations,
            }),
            crate::resource_plan::PlanProgress::Complete(response) => match *response {
                extension_api::ProviderResponse::Planned { mut plan } => {
                    if plan.mutation_domains.len() != 1
                        || plan.mutation_domains[0].domain != domain.domain
                        || plan.mutation_domains[0].expected_revision != domain.expected_revision
                    {
                        return Err(recovery("release_domain_changed"));
                    }
                    plan.mutation_domains[0] = domain;
                    plan.obligations = obligations;
                    Err(
                        serde_json::to_value(extension_api::ProviderResponse::Planned { plan })
                            .unwrap_or_else(|_| recovery("invalid_plan_response")),
                    )
                }
                other => Err(serde_json::to_value(other)
                    .unwrap_or_else(|_| recovery("invalid_plan_response"))),
            },
            crate::resource_plan::PlanProgress::Unknown => {
                Err(recovery("resource_planning_unknown"))
            }
        },
        PendingPhase::RefreshRelease {
            request,
            mut refresh,
            plans,
            obligations,
        } => match refresh.poll(now_ms, send) {
            crate::observation_refresh::RefreshProgress::Waiting => {
                Ok(PendingPhase::RefreshRelease {
                    request,
                    refresh,
                    plans,
                    obligations,
                })
            }
            crate::observation_refresh::RefreshProgress::Unknown => {
                Err(recovery("release_observation_unknown"))
            }
            crate::observation_refresh::RefreshProgress::Complete { domains, journals } => {
                let mut matching = journals
                    .into_iter()
                    .filter(|journal| journal.target == request.target);
                let expected = matching
                    .next()
                    .ok_or_else(|| recovery("release_ownership_unavailable"))?
                    .before;
                if matching.next().is_some() {
                    return Err(recovery("release_ownership_ambiguous"));
                }
                let epoch = crate::receipt_store::VerifiedEpoch::authenticate(
                    target_epoch(&request.target).to_owned(),
                    |_| true,
                )
                .map_err(rejected)?;
                let key = crate::durable_store::VerifiedTarget::authenticate(
                    target_store_key(&request.target).map_err(rejected)?,
                    |_| true,
                )
                .map_err(rejected)?;
                let mut store = crate::durable_store::VirtualDurableStateStore::new(
                    epoch,
                    key,
                    format!("planrelease.{request_id}"),
                    Some(request_id),
                    request.remaining_ms.min(30_000),
                )
                .map_err(rejected)?;
                store.start_load().map_err(rejected)?;
                Ok(PendingPhase::PlanReleaseLoad {
                    request,
                    expected: Box::new(expected),
                    domains,
                    plans,
                    obligations,
                    store: Box::new(store),
                })
            }
        },
        PendingPhase::PlanReleaseLoad {
            request,
            expected,
            domains,
            plans,
            obligations,
            mut store,
        } => {
            store.advance(now_ms, send);
            match store.poll_load() {
                LoadProgress::Waiting => Ok(PendingPhase::PlanReleaseLoad {
                    request,
                    expected,
                    domains,
                    plans,
                    obligations,
                    store,
                }),
                LoadProgress::Found(prior) => {
                    if prior != *expected {
                        return Err(recovery("release_journal_changed"));
                    }
                    let cleanup =
                        prior_virtual_cleanup(&prior, &plans, &obligations).map_err(recovery)?;
                    let mut matching = domains
                        .into_iter()
                        .filter(|domain| domain.domain == prior.domain_id);
                    let domain = matching
                        .next()
                        .ok_or_else(|| recovery("release_domain_unavailable"))?;
                    if matching.next().is_some() {
                        return Err(recovery("ambiguous_release_domain"));
                    }
                    let planner = crate::resource_plan::Planner::new_release(
                        LIFECYCLE_CALLER,
                        *request,
                        prior,
                        crate::resource_plan::ReleaseAuthority { domain, cleanup },
                        Some(request_id),
                        now_ms,
                        |_| true,
                    )
                    .map_err(rejected)?;
                    Ok(PendingPhase::Plan {
                        planner: Box::new(planner),
                    })
                }
                LoadProgress::Absent => Err(recovery("release_ownership_unavailable")),
                LoadProgress::Unknown => Err(recovery("release_ownership_unknown")),
            }
        }
        PendingPhase::PlanSessionLoad {
            mut planner,
            target,
            mut store,
        } => {
            store.advance(now_ms, send);
            match store.poll_load() {
                LoadProgress::Waiting => Ok(PendingPhase::PlanSessionLoad {
                    planner,
                    target,
                    store,
                }),
                LoadProgress::Found(obligation) => {
                    let session = crate::resource_plan::VerifiedSessionDisplay::authenticate(
                        target,
                        obligation,
                        |_, _| true,
                    )
                    .map_err(rejected)?;
                    planner.attach_session(session, now_ms).map_err(rejected)?;
                    Ok(PendingPhase::Plan { planner })
                }
                LoadProgress::Absent => Err(rejected("session_ownership_unverified")),
                LoadProgress::Unknown => Err(recovery("session_ownership_unknown")),
            }
        }
        PendingPhase::Plan { mut planner } => match planner.poll(now_ms, send) {
            crate::resource_plan::PlanProgress::Waiting => Ok(PendingPhase::Plan { planner }),
            crate::resource_plan::PlanProgress::Complete(response) => {
                Err(serde_json::to_value(response)
                    .unwrap_or_else(|_| recovery("invalid_plan_response")))
            }
            crate::resource_plan::PlanProgress::Unknown => {
                Err(recovery("resource_planning_unknown"))
            }
        },
        PendingPhase::StatusLookup { status, mut lookup } => match lookup.poll(now_ms, send) {
            crate::durable_store::PriorReceiptProgress::Waiting => {
                Ok(PendingPhase::StatusLookup { status, lookup })
            }
            crate::durable_store::PriorReceiptProgress::Expired => Err(recovery("receipt_expired")),
            crate::durable_store::PriorReceiptProgress::Unknown => {
                Err(recovery("receipt_lookup_unknown"))
            }
            crate::durable_store::PriorReceiptProgress::Found { receipt, request } => {
                if request.transition_id != status.transition_id {
                    return Err(recovery("receipt_identity_mismatch"));
                }
                let verification =
                    PendingVerification::from_request(LIFECYCLE_CALLER, &request, now_ms)
                        .map_err(|_| recovery("receipt_verification_unavailable"))?;
                Ok(PendingPhase::StatusVerify {
                    request,
                    receipt: Box::new(receipt),
                    verification: Box::new(verification),
                })
            }
        },
        PendingPhase::StatusVerify {
            request,
            receipt,
            mut verification,
        } => match verification.poll(now_ms, send) {
            Verification::Pending => Ok(PendingPhase::StatusVerify {
                request,
                receipt,
                verification,
            }),
            Verification::Verified => {
                if let crate::receipt_store::ReceiptState::Completed { result } = &receipt.state
                    && let Ok(crate::virtual_callback::CallbackResult::Prepared {
                        candidate,
                        obligations,
                    }) = serde_json::from_value(result.clone())
                {
                    let admitted = admitted_obligations(&request)
                        .map_err(|_| recovery("unowned_cleanup_obligation"))?;
                    if obligations != admitted {
                        return Err(recovery("receipt_obligation_mismatch"));
                    }
                    let epoch = crate::receipt_store::VerifiedEpoch::authenticate(
                        target_epoch(&request.target).to_owned(),
                        |_| true,
                    )
                    .map_err(|_| recovery("invalid_epoch"))?;
                    let target = crate::durable_store::VerifiedTarget::authenticate(
                        target_store_key(&request.target)
                            .map_err(|_| recovery("invalid_target"))?,
                        |_| true,
                    )
                    .map_err(|_| recovery("invalid_target"))?;
                    let mut store = crate::durable_store::VirtualDurableStateStore::new(
                        epoch,
                        target,
                        format!("statusbinding.{request_id}"),
                        None,
                        request.remaining_ms.min(30_000),
                    )
                    .map_err(|_| recovery("binding_store_unavailable"))?;
                    store
                        .start_load()
                        .map_err(|_| recovery("binding_store_unavailable"))?;
                    return Ok(PendingPhase::StatusBindingLoad {
                        request,
                        candidate,
                        obligations,
                        store: Box::new(store),
                    });
                }
                Err(receipt_response(&request, &receipt))
            }
            _ => Err(recovery("receipt_verification_unknown")),
        },
        PendingPhase::StatusBindingLoad {
            request,
            candidate,
            obligations,
            mut store,
        } => {
            store.advance(now_ms, send);
            let obligation = match store.poll_load() {
                LoadProgress::Waiting => {
                    return Ok(PendingPhase::StatusBindingLoad {
                        request,
                        candidate,
                        obligations,
                        store,
                    });
                }
                LoadProgress::Found(obligation) => obligation,
                _ => return Err(recovery("binding_obligation_unavailable")),
            };
            let Some(borrow) = obligation.borrow.as_ref() else {
                return Err(recovery("binding_borrow_unavailable"));
            };
            let validation = crate::virtual_callback::BindingValidationRequest {
                operation_id: format!("status.{}", request.provider_sequence),
                transition_id: request.transition_id.clone(),
                target: request.target.clone(),
                plan_revision: candidate.plan_revision,
                binding: (*candidate).clone(),
                observation: borrow.observed_output.clone(),
            };
            let validator = crate::virtual_callback::BindingValidator::new(
                LIFECYCLE_CALLER,
                validation,
                obligation,
                |_| true,
                request.remaining_ms.min(30_000),
                now_ms,
            )
            .map_err(|_| recovery("binding_validation_unavailable"))?;
            Ok(PendingPhase::StatusBinding {
                validator: Box::new(validator),
                store,
                candidate,
                obligations,
            })
        }
        PendingPhase::StatusBinding {
            mut validator,
            mut store,
            candidate,
            obligations,
        } => {
            store.advance(now_ms, send);
            match validator.poll(now_ms, send, &mut *store) {
                None => Ok(PendingPhase::StatusBinding {
                    validator,
                    store,
                    candidate,
                    obligations,
                }),
                Some(crate::virtual_callback::BindingValidationResult::Succeeded { .. }) => Err(
                    json!({"status":"prepared","candidate":candidate,"obligations":obligations}),
                ),
                _ => Err(recovery("binding_revalidation_required")),
            }
        }
        PendingPhase::Verify {
            request,
            mut verification,
        } => match verification.poll(now_ms, send) {
            Verification::Pending => Ok(PendingPhase::Verify {
                request,
                verification,
            }),
            Verification::Rejected => Err(rejected("coordinator_verification_rejected")),
            Verification::Unknown => Err(recovery("coordinator_verification_unknown")),
            Verification::Verified => {
                if request.operation == ProviderOperation::ResourcePlan {
                    if !preparing(&request)
                        && request
                            .settings
                            .get("display_target")
                            .and_then(Value::as_str)
                            .unwrap_or("virtual")
                            == "virtual"
                    {
                        let admitted = verification
                            .admitted_plans()
                            .ok_or_else(|| recovery("release_plans_unavailable"))?
                            .to_vec();
                        let obligations = verification
                            .obligations()
                            .ok_or_else(|| recovery("release_obligations_unavailable"))?
                            .to_vec();
                        let plans = admitted
                            .iter()
                            .filter(|p| {
                                p.target == request.target
                                    && matches!(
                                        p.phase,
                                        LifecyclePhase::SessionPrepare
                                            | LifecyclePhase::StreamPrepare
                                    )
                            })
                            .map(|p| p.plan.clone())
                            .collect();
                        let refresh = crate::observation_refresh::ObservationRefresh::new(
                            request.target.clone(),
                            admitted,
                            obligations.clone(),
                            Some(request_id),
                            request.remaining_ms.min(30_000),
                            now_ms,
                            |_, _, _| true,
                        )
                        .map_err(rejected)?;
                        return Ok(PendingPhase::RefreshRelease {
                            request,
                            refresh: Box::new(refresh),
                            plans,
                            obligations,
                        });
                    }
                    if !preparing(&request)
                        && request
                            .settings
                            .get("display_target")
                            .and_then(Value::as_str)
                            == Some("physical")
                    {
                        let domains = verification
                            .mutation_domains()
                            .ok_or_else(|| recovery("release_domains_unavailable"))?
                            .to_vec();
                        let epoch = crate::receipt_store::VerifiedEpoch::authenticate(
                            target_epoch(&request.target).to_owned(),
                            |_| true,
                        )
                        .map_err(rejected)?;
                        let key = crate::durable_store::VerifiedTarget::authenticate(
                            target_store_key(&request.target).map_err(rejected)?,
                            |_| true,
                        )
                        .map_err(rejected)?;
                        let mut store = crate::durable_store::StateDurableStore::new(
                            epoch,
                            key,
                            format!("planrelease.{request_id}"),
                            Some(request_id),
                            request.remaining_ms.min(30_000),
                        )
                        .map_err(rejected)?;
                        store.start_load().map_err(rejected)?;
                        let plans = verification
                            .plans()
                            .ok_or_else(|| recovery("release_plans_unavailable"))?
                            .to_vec();
                        let obligations = verification
                            .obligations()
                            .ok_or_else(|| recovery("release_obligations_unavailable"))?
                            .to_vec();
                        return Ok(PendingPhase::PhysicalReleaseLoad {
                            request,
                            domains,
                            plans,
                            obligations,
                            store: Box::new(store),
                        });
                    }
                    let needs_session = matches!(request.target, LifecycleTarget::Stream { .. })
                        && request
                            .settings
                            .get("display_target")
                            .and_then(Value::as_str)
                            .unwrap_or("virtual")
                            == "virtual";
                    let session_target = verification.session_target().cloned();
                    let timeout = request.remaining_ms.min(30_000);
                    let planner = crate::resource_plan::Planner::new(
                        LIFECYCLE_CALLER,
                        *request,
                        Some(request_id),
                        now_ms,
                        |_| true,
                    )
                    .map_err(rejected)?;
                    if needs_session {
                        let target =
                            session_target.ok_or_else(|| recovery("session_target_unavailable"))?;
                        let epoch = crate::receipt_store::VerifiedEpoch::authenticate(
                            target_epoch(&target).to_owned(),
                            |_| true,
                        )
                        .map_err(rejected)?;
                        let key = crate::durable_store::VerifiedTarget::authenticate(
                            target_store_key(&target).map_err(rejected)?,
                            |_| true,
                        )
                        .map_err(rejected)?;
                        let mut store = crate::durable_store::VirtualDurableStateStore::new(
                            epoch,
                            key,
                            format!("plansession.{request_id}"),
                            Some(request_id),
                            timeout,
                        )
                        .map_err(rejected)?;
                        store.start_load().map_err(rejected)?;
                        return Ok(PendingPhase::PlanSessionLoad {
                            planner: Box::new(planner),
                            target,
                            store: Box::new(store),
                        });
                    }
                    return Ok(PendingPhase::Plan {
                        planner: Box::new(planner),
                    });
                }
                if !matches!(
                    send(Command::CheckRequest {
                        request: request_id
                    }),
                    Ok(Response::Ok)
                ) {
                    return Err(recovery("request_ended_before_effect"));
                }
                start_effect(request).map_err(rejected)
            }
        },
        PendingPhase::PhysicalLoad { request, mut store } => {
            store.advance(now_ms, send);
            let prior = match store.poll_load() {
                LoadProgress::Waiting => return Ok(PendingPhase::PhysicalLoad { request, store }),
                LoadProgress::Found(prior) if !preparing(&request) => Some(prior),
                LoadProgress::Found(prior) if preparing(&request) && prior.restored => None,
                LoadProgress::Absent if preparing(&request) => None,
                _ => return Err(recovery("obligation_reconciliation_required")),
            };
            let obligations = admitted_obligations(&request).map_err(rejected)?;
            let parent = preparing(&request).then_some(request_id);
            let machine = crate::physical_callback::PhysicalCallback::new(
                LIFECYCLE_CALLER,
                *request,
                prior,
                |_| true,
                now_ms,
                parent,
            )
            .map_err(rejected)?;
            Ok(PendingPhase::Physical {
                machine: Box::new(machine),
                store,
                obligations,
                guard: Box::new(LiveEffectGuard::default()),
            })
        }
        PendingPhase::VirtualLoad { request, mut store } => {
            store.advance(now_ms, send);
            let prior = match store.poll_load() {
                LoadProgress::Waiting => return Ok(PendingPhase::VirtualLoad { request, store }),
                LoadProgress::Found(prior) if !preparing(&request) => Some(prior),
                LoadProgress::Found(prior)
                    if preparing(&request)
                        && prior.reference_released
                        && prior.borrow.is_none() =>
                {
                    None
                }
                LoadProgress::Absent if preparing(&request) => None,
                _ => return Err(recovery("obligation_reconciliation_required")),
            };
            let obligations = admitted_obligations(&request).map_err(rejected)?;
            let parent = preparing(&request).then_some(request_id);
            let machine = crate::virtual_callback::VirtualCallback::new(
                LIFECYCLE_CALLER,
                *request,
                prior,
                |_| true,
                now_ms,
                parent,
            )
            .map_err(rejected)?;
            Ok(PendingPhase::Virtual {
                machine: Box::new(machine),
                store,
                obligations,
                guard: Box::new(LiveEffectGuard::default()),
            })
        }
        PendingPhase::BindingLoad {
            request,
            mut store,
            timeout_ms,
        } => {
            store.advance(now_ms, send);
            let obligation = match store.poll_load() {
                LoadProgress::Waiting => {
                    return Ok(PendingPhase::BindingLoad {
                        request,
                        store,
                        timeout_ms,
                    });
                }
                LoadProgress::Found(obligation) => obligation,
                _ => return Err(recovery("binding_obligation_unavailable")),
            };
            let validator = crate::virtual_callback::BindingValidator::new(
                LIFECYCLE_CALLER,
                *request,
                obligation,
                |_| true,
                timeout_ms,
                now_ms,
            )
            .map_err(rejected)?;
            Ok(PendingPhase::Binding {
                validator: Box::new(validator),
                store,
            })
        }
        PendingPhase::Binding {
            mut validator,
            mut store,
        } => {
            store.advance(now_ms, send);
            match validator.poll(now_ms, send, &mut *store) {
                None => Ok(PendingPhase::Binding { validator, store }),
                Some(result) => Err(serde_json::to_value(result)
                    .unwrap_or_else(|_| recovery("binding_result_invalid"))),
            }
        }
        PendingPhase::Physical {
            mut machine,
            mut store,
            obligations,
            mut guard,
        } => {
            store.advance(now_ms, send);
            match machine.poll(now_ms, send, &mut *store, &mut *guard) {
                crate::physical_callback::CallbackProgress::Waiting => Ok(PendingPhase::Physical {
                    machine,
                    store,
                    obligations,
                    guard,
                }),
                crate::physical_callback::CallbackProgress::Complete(
                    crate::physical_callback::CallbackResult::Applied { .. },
                ) => Err(json!({"status":"prepared","candidate":null,"obligations":obligations})),
                crate::physical_callback::CallbackProgress::Complete(
                    crate::physical_callback::CallbackResult::Restored { .. },
                ) => Err(cleanup(&obligations)),
                crate::physical_callback::CallbackProgress::Complete(
                    crate::physical_callback::CallbackResult::Rejected { reason },
                ) => Err(rejected(&reason)),
                _ => Err(recovery("physical_recovery_required")),
            }
        }
        PendingPhase::Virtual {
            mut machine,
            mut store,
            obligations,
            mut guard,
        } => {
            store.advance(now_ms, send);
            match machine.poll(now_ms, send, &mut *store, &mut *guard) {
                crate::virtual_callback::CallbackProgress::Waiting => Ok(PendingPhase::Virtual {
                    machine,
                    store,
                    obligations,
                    guard,
                }),
                crate::virtual_callback::CallbackProgress::Complete(
                    crate::virtual_callback::CallbackResult::Prepared {
                        candidate,
                        obligations,
                    },
                ) => Err(
                    json!({"status":"prepared","candidate":candidate,"obligations":obligations}),
                ),
                crate::virtual_callback::CallbackProgress::Complete(
                    crate::virtual_callback::CallbackResult::Released,
                ) => Err(cleanup(&obligations)),
                crate::virtual_callback::CallbackProgress::Complete(
                    crate::virtual_callback::CallbackResult::Rejected { reason },
                ) => Err(rejected(&reason)),
                _ => Err(recovery("virtual_recovery_required")),
            }
        }
    }
}
impl DisplaySettingsModule {
    fn complete(&self, id: u64, payload: Value) -> ModuleResult<()> {
        match self.runtime.send(Command::Complete {
            request: id,
            payload,
        })? {
            Response::Ok => Ok(()),
            Response::Error { code, .. } if code == "request_ended" || code == "not_found" => {
                Ok(())
            }
            _ => Err("display provider completion failed".into()),
        }
    }
    fn advance(&mut self) -> ModuleResult<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let mut item = self.pending.remove(0);
        let now = self.clock.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        match advance_phase(item.phase, item.request_id, now, &mut |command| {
            self.runtime.send(command)
        }) {
            Ok(phase) => {
                item.phase = phase;
                self.pending.push(item);
            }
            Err(response) => self.complete(item.request_id, response)?,
        }
        Ok(())
    }
}
impl ManagedModule for DisplaySettingsModule {
    fn start(runtime: RuntimeClient) -> ModuleResult<Self> {
        for &name in REGISTERED_METHODS {
            runtime.require_success(registration(name))?;
        }
        Ok(Self {
            runtime,
            clock: Instant::now(),
            pending: Vec::new(),
        })
    }
    fn tick(&mut self) -> ModuleResult<()> {
        self.advance()?;
        match self.runtime.send(Command::Poll {})? {
            Response::Pending => Ok(()),
            Response::Request {
                id,
                caller,
                service,
                payload,
                remaining_ms,
                ..
            } => {
                if service != SERVICE
                    || !matches!(
                        self.runtime.send(Command::CheckRequest { request: id })?,
                        Response::Ok
                    )
                {
                    return Ok(());
                }
                if arguments(&payload).is_some_and(|(method, _)| method == "settings_validate") {
                    return self.complete(id, validate_request(&caller, payload));
                }
                let now = self.clock.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                match dispatch(&caller, &payload, now, remaining_ms) {
                    Dispatch::Immediate(result) => self.complete(id, result),
                    Dispatch::ActionPlan(request) if self.pending.len() < MAX_PENDING => {
                        match crate::action_provider::ActionPlanner::new(
                            crate::action_provider::ACTION_CALLER,
                            (*request).clone(),
                            id,
                            now,
                            remaining_ms.min(30_000),
                        ) {
                            Ok(planner) => {
                                self.pending.push(PendingRequest {
                                    request_id: id,
                                    phase: PendingPhase::ActionPlan {
                                        planner: Box::new(planner),
                                        request,
                                    },
                                });
                                Ok(())
                            }
                            Err(reason) => self.complete(id, rejected(reason)),
                        }
                    }
                    Dispatch::ActionPlan(_) => self.complete(id, rejected("provider_busy")),
                    Dispatch::ActionExecute(request) if self.pending.len() < MAX_PENDING => {
                        match start_action_execute(request, id, now, remaining_ms) {
                            Ok(phase) => {
                                self.pending.push(PendingRequest {
                                    request_id: id,
                                    phase,
                                });
                                Ok(())
                            }
                            Err(reason) => self.complete(id, rejected(reason)),
                        }
                    }
                    Dispatch::ActionExecute(_) => self.complete(id, rejected("provider_busy")),
                    Dispatch::ActionStatus(request) if self.pending.len() < MAX_PENDING => {
                        match crate::action_store::DurableActionStore::new(
                            crate::action_provider::ACTION_CALLER,
                            format!("action-status.{id}"),
                            Some(id),
                            remaining_ms.min(30_000),
                            |_| true,
                        ) {
                            Ok(store) => {
                                self.pending.push(PendingRequest {
                                    request_id: id,
                                    phase: PendingPhase::ActionStatus {
                                        request,
                                        store: Box::new(store),
                                    },
                                });
                                Ok(())
                            }
                            Err(reason) => self.complete(id, rejected(reason)),
                        }
                    }
                    Dispatch::ActionStatus(_) => self.complete(id, rejected("provider_busy")),
                    Dispatch::Verify(request, verification) if self.pending.len() < MAX_PENDING => {
                        self.pending.push(PendingRequest {
                            request_id: id,
                            phase: PendingPhase::Verify {
                                request,
                                verification,
                            },
                        });
                        Ok(())
                    }
                    Dispatch::Verify(_, _) => self.complete(id, rejected("provider_busy")),
                    Dispatch::Binding(request) if self.pending.len() < MAX_PENDING => {
                        match start_binding(request, id, remaining_ms) {
                            Ok(phase) => {
                                self.pending.push(PendingRequest {
                                    request_id: id,
                                    phase,
                                });
                                Ok(())
                            }
                            Err(reason) => self.complete(id, rejected(reason)),
                        }
                    }
                    Dispatch::Binding(_) => self.complete(id, rejected("provider_busy")),
                    Dispatch::Status(status) if self.pending.len() < MAX_PENDING => {
                        let lookup = crate::durable_store::PriorReceiptLookup::new(
                            LIFECYCLE_CALLER,
                            status.provider_sequence,
                            status.operation_id.clone(),
                            format!("status.{id}"),
                            None,
                            remaining_ms.min(30_000),
                            now,
                        );
                        match lookup {
                            Ok(lookup) => {
                                self.pending.push(PendingRequest {
                                    request_id: id,
                                    phase: PendingPhase::StatusLookup {
                                        status,
                                        lookup: Box::new(lookup),
                                    },
                                });
                                Ok(())
                            }
                            Err(_) => self.complete(id, recovery("receipt_lookup_unavailable")),
                        }
                    }
                    Dispatch::Status(_) => self.complete(id, rejected("provider_busy")),
                }
            }
            _ => Err("display provider polling failed".into()),
        }
    }
}
amaterasu_module_sdk::export_module!(DisplaySettingsModule);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    #[test]
    fn validates_only_complete_settings_from_registry() {
        let values =
            amaterasu_configuration_schema::defaults(&crate::settings_schema::definitions())
                .unwrap();
        let request = json!({"method":"settings_validate","interface_major":1,"interface_minor":0,"arguments":{"values":values}});
        assert_eq!(
            validate_request(REGISTRY_CALLER, request.clone())["valid"],
            true
        );
        assert_eq!(validate_request("untrusted", request)["valid"], false);
        for method in [
            "settings_validate",
            "resource_plan",
            "lifecycle_callback",
            "lifecycle_status",
            "binding_validate",
        ] {
            assert!(matches!(registration(method), Command::RegisterApi { .. }));
        }
    }
    #[test]
    fn untrusted_and_unavailable_binding_never_authorize() {
        let request = json!({"method":"binding_validate","interface_major":1,"interface_minor":0,"arguments":{}});
        assert!(
            matches!(dispatch("attacker",&request,0,100),Dispatch::Immediate(v) if v["status"]=="rejected")
        );
        assert!(
            matches!(dispatch(LIFECYCLE_CALLER,&request,0,100),Dispatch::Immediate(v) if v["status"]=="rejected")
        );
    }
    #[test]
    fn checked_in_approvals_match_registered_method_contracts() {
        let actual: Value =
            serde_json::from_str(include_str!("../examples/lifecycle-api-approvals.json")).unwrap();
        let expected: Vec<Value> = REGISTERED_METHODS
            .iter()
            .copied()
            .map(|name| {
                let Command::RegisterApi { method } = registration(name) else {
                    unreachable!()
                };
                let callers = if name == "settings_validate" {
                    vec![REGISTRY_CALLER, "amaterasu.management"]
                } else if name.starts_with("action_") {
                    vec![crate::action_provider::ACTION_CALLER]
                } else {
                    vec![LIFECYCLE_CALLER]
                };
                json!({"provider":crate::descriptor::PROVIDER,"callers":callers,"method":method})
            })
            .collect();
        assert_eq!(actual, json!({"api_methods":expected}));
    }
    #[test]
    #[ignore = "prints example operator approvals for packaging"]
    fn print_example_api_approvals() {
        let approvals: Vec<_> = REGISTERED_METHODS
            .iter()
            .copied()
            .map(|name| {
                let Command::RegisterApi { method } = registration(name) else {
                    unreachable!()
                };
                let callers = if name == "settings_validate" {
                    vec![REGISTRY_CALLER, "amaterasu.management"]
                } else if name.starts_with("action_") {
                    vec![crate::action_provider::ACTION_CALLER]
                } else {
                    vec![LIFECYCLE_CALLER]
                };
                json!({"provider":crate::descriptor::PROVIDER,"callers":callers,"method":method})
            })
            .collect();
        println!("APPROVALS_JSON={}", json!({"api_methods":approvals}));
    }
    fn callback_request() -> ProviderRequest {
        serde_json::from_value(json!({"provider_sequence":1,"operation":"lifecycle_callback","version":1,"transition_id":"transition-1","operation_id":"virtual-1","target":{"kind":"stream","host_epoch":"epoch-1","session_id":"session-1","stream_id":"stream-1","generation":7},"phase":"stream.prepare","settings_revision":"settings-1","settings":{},"intent":"initial","reason":null,"requested_video":null,"consumer_requirements":{"execution_domain":"desktop","capture_providers":["amaterasu.capture-pipewire/1"],"selector_schemas":["amaterasu.kwin-wl-output/1"]},"remaining_ms":5000,"plan_revision":1,"admission_id":"admission-1","approved_plan":{"plan_id":"plan-1","revision":1,"resources":[{"provider":crate::descriptor::PROVIDER,"resource_id":"9c1d707f-7229-4fc4-b6e2-91f80c626a09","incarnation":null,"expected_revision":null,"execution_domain":"desktop","mutation_domains":["provider_session:abcdef"],"access":"exclusive"}],"mutation_domains":[{"domain":"provider_session:abcdef","expected_revision":1,"borrowers":{},"access":"exclusive"}],"required_capabilities":[],"constraints":{"virtual_display":{"provider_service":"amaterasu.virtual-display/1","identity":"9c1d707f-7229-4fc4-b6e2-91f80c626a09","reference_id":"stream-1","width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false,"scale":null,"layout":"extended","domain_id":"provider_session:abcdef","domain_revision":1,"geometry_revision":3,"borrow":null,"reference_released":false}},"obligations":[{"obligation_id":"cleanup-1","provider":"nonary.display-settings","resource_id":"9c1d707f-7229-4fc4-b6e2-91f80c626a09","mutation_domain":"provider_session:abcdef","depends_on":[],"cleanup_method":{"service":"nonary.display-settings/1","method":"lifecycle_callback","interface_major":1,"interface_minor":0,"schema_revision":1},"payload":{"service":"amaterasu.virtual-display/1","identity":"9c1d707f-7229-4fc4-b6e2-91f80c626a09","reference_id":"stream-1"}}],"affected_consumers":[],"consumer_change":"reconnect_required","candidate_constraint":{"capture_provider":"amaterasu.capture-pipewire/1","selector_schema":"amaterasu.kwin-wl-output/1","resource_provider":crate::descriptor::PROVIDER,"resource_id":"9c1d707f-7229-4fc4-b6e2-91f80c626a09","incarnation":null,"execution_domain":"desktop","mode":{"width":1920,"height":1080,"refresh_millihz":60000,"hdr":false},"plan_revision":1},"allowed_degradation":[]}})).unwrap()
    }
    #[test]
    fn release_requires_exact_live_coordinator_cleanup_and_unambiguous_prior_plan() {
        let request = callback_request();
        let plan = request.approved_plan.unwrap();
        let prior: crate::virtual_callback::VirtualObligation =
            serde_json::from_value(plan.constraints["virtual_display"].clone()).unwrap();
        let owned = plan.obligations.clone();
        assert_eq!(
            prior_virtual_cleanup(&prior, std::slice::from_ref(&plan), &owned).unwrap(),
            owned[0]
        );
        assert_eq!(
            prior_virtual_cleanup(&prior, std::slice::from_ref(&plan), &[]).unwrap_err(),
            "release_prior_plan_unavailable"
        );
        assert_eq!(
            prior_virtual_cleanup(&prior, &[plan.clone(), plan], &owned).unwrap_err(),
            "release_prior_plan_ambiguous"
        );
    }
    #[derive(Default)]
    struct FakeBroker {
        state_revision: u64,
        values: std::collections::BTreeMap<String, Value>,
        collection_revision: u64,
        metadata: Value,
        entries: std::collections::BTreeMap<String, Value>,
        pending: std::collections::BTreeMap<u64, Value>,
        next: u64,
        effects: Vec<String>,
        deny_after_checks: Option<usize>,
        check_count: usize,
        borrow_invalid: bool,
        action_description: Option<Value>,
        action_collections: std::collections::BTreeMap<
            String,
            (u64, Value, std::collections::BTreeMap<String, Value>),
        >,
    }
    impl FakeBroker {
        fn send(&mut self, command: Command) -> ModuleResult<Response> {
            match command {
                Command::CheckRequest { .. } => {
                    self.check_count += 1;
                    if self
                        .deny_after_checks
                        .is_some_and(|allowed| self.check_count > allowed)
                    {
                        Ok(Response::Error {
                            code: "request_ended".into(),
                            message: "expired".into(),
                        })
                    } else {
                        Ok(Response::Ok)
                    }
                }
                Command::Request {
                    service, payload, ..
                } => {
                    let response = if service == "amaterasu.state/1"
                        && payload["collection"]
                            .as_str()
                            .is_some_and(|name| name.starts_with("display-settings/action-"))
                    {
                        let name = payload["collection"].as_str().unwrap().to_owned();
                        let (revision, metadata, values) =
                            self.action_collections.entry(name).or_default();
                        match payload["action"].as_str().unwrap() {
                            "collection_get" => {
                                json!({"ok":true,"revision":*revision,"found":*revision!=0,"metadata":metadata,"count":values.len(),"value":values.get(payload["key"].as_str().unwrap())})
                            }
                            "collection_commit" => {
                                assert_eq!(payload["expected_revision"].as_u64(), Some(*revision));
                                for edit in payload["edits"].as_array().unwrap() {
                                    let key = edit["key"].as_str().unwrap().to_owned();
                                    if edit["value"].is_null() {
                                        values.remove(&key);
                                    } else {
                                        values.insert(key, edit["value"].clone());
                                    }
                                }
                                *metadata = payload["metadata"].clone();
                                *revision += 1;
                                json!({"ok":true,"revision":*revision})
                            }
                            _ => panic!("unexpected action collection"),
                        }
                    } else if service == "amaterasu.state/1" {
                        match payload["action"].as_str().unwrap() {
                            "get" => {
                                let value = self.values.get(payload["key"].as_str().unwrap());
                                json!({"ok":true,"revision":self.state_revision,"found":value.is_some(),"value":value})
                            }
                            "set" => {
                                assert_eq!(
                                    payload["expected_revision"].as_u64(),
                                    Some(self.state_revision)
                                );
                                self.values.insert(
                                    payload["key"].as_str().unwrap().into(),
                                    payload["value"].clone(),
                                );
                                self.state_revision += 1;
                                json!({"ok":true,"revision":self.state_revision})
                            }
                            "collection_get" => {
                                json!({"ok":true,"revision":self.collection_revision,"found":self.collection_revision!=0,"metadata":self.metadata,"count":self.entries.len(),"value":self.entries.get(payload["key"].as_str().unwrap())})
                            }
                            "collection_commit" => {
                                assert_eq!(
                                    payload["expected_revision"].as_u64(),
                                    Some(self.collection_revision)
                                );
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
                            _ => panic!("unexpected state operation"),
                        }
                    } else if service == "amaterasu.session-lifecycle/1"
                        && payload["operation"] == "describe_action_target"
                    {
                        self.action_description.clone().expect("action description")
                    } else if service == "amaterasu.session-lifecycle/1"
                        && payload["operation"] == "refresh_provider_observations"
                    {
                        let domain = &payload["domains"][0];
                        json!({"status":"succeeded","operation_id":payload["operation_id"],"target":payload["target"],"mutation_domains":[{"domain":domain["domain"],"expected_revision":domain["revision"],"borrowers":domain["borrowers"],"access":"exclusive"}],"stale_mutation_domains":[]})
                    } else if service == "amaterasu.session-lifecycle/1" {
                        let mut answer = payload;
                        answer["status"] = "succeeded".into();
                        match answer["target"]["kind"].as_str() {
                            Some("session") => answer["session_target"] = answer["target"].clone(),
                            Some("stream") => {
                                answer["session_target"] = json!({"kind":"session","host_epoch":answer["target"]["host_epoch"],"session_id":answer["target"]["session_id"],"generation":1})
                            }
                            _ => {}
                        }
                        answer
                    } else if service == "amaterasu.virtual-display/1" {
                        let action = payload["action"].as_str().unwrap();
                        self.effects.push(action.into());
                        let domain = json!({"id":"provider_session:abcdef","revision":2,"borrowers":1,"pending_mutations":0,"scope":"provider_session"});
                        match action {
                            "status" => {
                                json!({"ok":true,"enabled":true,"native_supported":true,"recovery_ready":true,"mutation_domain":domain})
                            }
                            "create" => {
                                assert!(self.metadata["pending"] == 1);
                                assert!(self.values.values().any(|value| value["identity"]
                                    == "9c1d707f-7229-4fc4-b6e2-91f80c626a09"));
                                json!({"ok":true,"reference_owned":true,"monitor":{"specification":{"identity":"9c1d707f-7229-4fc4-b6e2-91f80c626a09","width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false},"virtual_display_layout":"extended","dd_virtual_display_scale":0,"state":"ready","error":null,"ready":{"device_path":"Virtual-1","active":true},"capture_output":"kwin:Virtual-1"}})
                            }
                            "validate_borrow" if self.borrow_invalid => {
                                json!({"ok":false,"code":"borrow_invalid"})
                            }
                            "borrow" | "validate_borrow" => {
                                json!({"ok":true,"borrow_id":"a".repeat(64),"observed_output":{"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1920,"height":1080,"refresh_millihz":60000},"mutation_domain":domain})
                            }
                            "release_borrow" => {
                                json!({"ok":true,"released":true,"mutation_domain":domain})
                            }
                            "remove" => {
                                json!({"ok":true,"removed":true,"identity":"9c1d707f-7229-4fc4-b6e2-91f80c626a09"})
                            }
                            _ => panic!("unexpected provider operation"),
                        }
                    } else {
                        panic!("unexpected service {service}")
                    };
                    self.next += 1;
                    self.pending.insert(self.next, response);
                    Ok(Response::Accepted { id: self.next })
                }
                Command::TakeResult { request } => Ok(Response::Result {
                    payload: self.pending.get(&request).unwrap().clone(),
                }),
                Command::ReleaseResult { request } => {
                    self.pending.remove(&request);
                    Ok(Response::Ok)
                }
                _ => panic!("unexpected broker command"),
            }
        }
        fn status(&mut self, sequence: u64, operation_id: &str) -> Value {
            let status = ProviderStatusRequest {
                provider_sequence: sequence,
                operation_id: operation_id.into(),
                transition_id: "transition-1".into(),
                receipt_id: operation_id.into(),
            };
            let lookup = crate::durable_store::PriorReceiptLookup::new(
                LIFECYCLE_CALLER,
                sequence,
                operation_id.into(),
                format!("status.{sequence}"),
                None,
                5000,
                0,
            )
            .unwrap();
            let mut phase = PendingPhase::StatusLookup {
                status: Box::new(status),
                lookup: Box::new(lookup),
            };
            for tick in 1..200 {
                match advance_phase(phase, 77, tick, &mut |cmd| self.send(cmd)) {
                    Ok(next) => phase = next,
                    Err(result) => return result,
                }
            }
            panic!("status did not settle")
        }
        fn drive_effect(&mut self, request: ProviderRequest) -> Value {
            let verify = PendingVerification::from_request(LIFECYCLE_CALLER, &request, 0).unwrap();
            let mut phase = PendingPhase::Verify {
                request: Box::new(request),
                verification: Box::new(verify),
            };
            for tick in 4..200 {
                match advance_phase(phase, 77, tick, &mut |cmd| self.send(cmd)) {
                    Ok(next) => phase = next,
                    Err(result) => return result,
                }
            }
            panic!("effect did not settle")
        }
    }
    #[test]
    fn verified_virtual_prepare_and_release_persist_before_native_effects() {
        let mut broker = FakeBroker::default();
        let mut prepare = callback_request();
        let response = broker.drive_effect(prepare.clone());
        assert_eq!(response["status"], "prepared");
        assert_eq!(
            response["candidate"]["resource"]["incarnation"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(broker.effects, ["create", "borrow", "validate_borrow"]);
        let status = broker.status(1, "virtual-1");
        assert_eq!(status["status"], "prepared");
        assert_eq!(status["candidate"], response["candidate"]);
        assert_eq!(
            broker.effects,
            ["create", "borrow", "validate_borrow", "validate_borrow"]
        );
        broker.borrow_invalid = true;
        assert_eq!(broker.status(1, "virtual-1")["status"], "recovery_required");
        broker.borrow_invalid = false;
        prepare.provider_sequence = 2;
        prepare.operation_id = "virtual-2".into();
        prepare.phase = LifecyclePhase::StreamRelease;
        prepare.reason = Some(extension_api::ReleaseReason::Pause);
        let response = broker.drive_effect(prepare);
        assert_eq!(response["status"], "cleanup");
        assert_eq!(response["outcomes"][0]["state"], "released");
        assert_eq!(
            broker.effects,
            [
                "create",
                "borrow",
                "validate_borrow",
                "validate_borrow",
                "validate_borrow",
                "release_borrow",
                "remove"
            ]
        );
        assert!(
            broker
                .values
                .values()
                .any(|value| value["reference_released"] == true && value["borrow"].is_null())
        );
    }
    #[test]
    fn expired_callback_after_durable_reservation_never_creates_display() {
        let mut broker = FakeBroker {
            deny_after_checks: Some(1),
            ..Default::default()
        };
        let response = broker.drive_effect(callback_request());
        assert_eq!(response["status"], "recovery_required");
        assert!(broker.effects.is_empty());
        assert_eq!(broker.metadata["pending"], 1);
    }
    #[test]
    fn stream_plan_requires_and_revalidates_coordinator_selected_session_journal() {
        let mut request = callback_request();
        request.operation = ProviderOperation::ResourcePlan;
        request.plan_revision = None;
        request.admission_id = None;
        request.approved_plan = None;
        request.requested_video = Some(
            serde_json::from_value(
                json!({"width":1920,"height":1080,"refresh_millihz":60000,"hdr":false}),
            )
            .unwrap(),
        );
        request.settings =
            amaterasu_configuration_schema::defaults(&crate::settings_schema::definitions())
                .unwrap();
        request.settings.insert("enabled".into(), json!(true));
        let mut missing = FakeBroker::default();
        let result = missing.drive_effect(request.clone());
        assert_eq!(result["reason"], "session_ownership_unverified");
        assert!(missing.effects.is_empty());

        let mut broker = FakeBroker::default();
        assert_eq!(
            broker.drive_effect(callback_request())["status"],
            "prepared"
        );
        let mut obligation = broker
            .values
            .values()
            .find(|v| v.get("reference_released").is_some())
            .unwrap()
            .clone();
        obligation["identity"] = json!("6f410583-4b76-5ba6-bf99-0745617106eb");
        obligation["reference_id"] = json!("ref-dbfc1a77bc181a02b199997ec5e877fc");
        let session = LifecycleTarget::Session {
            host_epoch: "epoch-1".into(),
            session_id: "session-1".into(),
            generation: 1,
        };
        broker.values.insert(
            format!(
                "virtual-obligation/v1/{}",
                target_store_key(&session).unwrap()
            ),
            obligation,
        );
        broker.effects.clear();
        let verify = PendingVerification::from_request(LIFECYCLE_CALLER, &request, 0).unwrap();
        let mut phase = PendingPhase::Verify {
            request: Box::new(request),
            verification: Box::new(verify),
        };
        for tick in 1..100 {
            phase = advance_phase(phase, 77, tick, &mut |cmd| broker.send(cmd))
                .unwrap_or_else(|v| panic!("unexpected result {v}"));
            if broker
                .effects
                .iter()
                .any(|effect| effect == "validate_borrow")
            {
                return;
            }
        }
        panic!("session borrow was not validated");
    }
    #[test]
    fn target_key_preserves_full_uuid_identity_and_generation() {
        let make = |generation| LifecycleTarget::Stream {
            host_epoch: "12345678-1234-1234-1234-123456789abc".into(),
            session_id: "12345678-1234-1234-1234-123456789abc".into(),
            stream_id: "12345678-1234-1234-1234-123456789abc".into(),
            generation,
        };
        let original = target_store_key(&make(7)).unwrap();
        assert_eq!(original.len(), 71);
        assert_eq!(original, target_store_key(&make(7)).unwrap());
        assert_ne!(original, target_store_key(&make(8)).unwrap());
        assert!(crate::durable_store::VerifiedTarget::authenticate(original, |_| true).is_ok());
    }
    #[test]
    fn status_unknown_receipt_never_replays_or_reports_success() {
        let status = ProviderStatusRequest {
            provider_sequence: 1,
            operation_id: "op-1".into(),
            transition_id: "transition-1".into(),
            receipt_id: "op-1".into(),
        };
        let lookup = crate::durable_store::PriorReceiptLookup::new(
            LIFECYCLE_CALLER,
            1,
            "op-1".into(),
            "status.1".into(),
            None,
            100,
            0,
        )
        .unwrap();
        let mut calls = VecDeque::from([
            Response::Accepted { id: 2 },
            Response::Result {
                payload: json!({"ok":true,"revision":0,"found":false,"count":0,"metadata":null}),
            },
            Response::Ok,
        ]);
        let mut send = |command| {
            assert!(matches!(
                command,
                Command::Request { .. }
                    | Command::TakeResult { .. }
                    | Command::ReleaseResult { .. }
            ));
            Ok(calls.pop_front().unwrap())
        };
        let phase = PendingPhase::StatusLookup {
            status: Box::new(status),
            lookup: Box::new(lookup),
        };
        let phase = match advance_phase(phase, 77, 1, &mut send) {
            Ok(phase) => phase,
            Err(_) => panic!("unexpected completion"),
        };
        let phase = match advance_phase(phase, 77, 2, &mut send) {
            Ok(phase) => phase,
            Err(_) => panic!("unexpected completion"),
        };
        assert!(
            matches!(advance_phase(phase,77,3,&mut send),Err(value) if value["status"]=="recovery_required")
        );
    }
    #[test]
    fn effect_guard_reverifies_each_submission_and_checks_live_parent() {
        use crate::virtual_callback::{EffectGuard, EffectKind, GuardProgress};
        let request: ProviderRequest = serde_json::from_value(json!({"provider_sequence":1,"operation":"resource_plan","version":1,"transition_id":"transition-1","operation_id":"op-1","target":{"kind":"validation","host_epoch":"epoch-1","validation_id":"validation-1","generation":1},"phase":"stream.prepare","settings_revision":"revision","settings":{},"intent":null,"reason":null,"requested_video":null,"consumer_requirements":{"execution_domain":"desktop","capture_providers":["capture"],"selector_schemas":["selector/1"]},"remaining_ms":100,"plan_revision":null,"admission_id":null,"approved_plan":null})).unwrap();
        let mut guard = LiveEffectGuard::default();
        let mut payload = Value::Null;
        let mut transport_ids = Vec::new();
        let mut send = |command| match command {
            Command::Request {
                payload: request,
                operation_id,
                ..
            } => {
                payload = request;
                transport_ids.push(operation_id);
                Ok(Response::Accepted { id: 1 })
            }
            Command::TakeResult { .. } => {
                let mut reply = payload.clone();
                reply["status"] = "succeeded".into();
                Ok(Response::Result { payload: reply })
            }
            Command::ReleaseResult { .. } | Command::CheckRequest { request: 77 } => {
                Ok(Response::Ok)
            }
            _ => panic!("unexpected command"),
        };
        for effect in [EffectKind::Create, EffectKind::Borrow] {
            assert_eq!(
                guard.poll(&request, effect, 77, 1, &mut send),
                GuardProgress::Waiting
            );
            assert_eq!(
                guard.poll(&request, effect, 77, 2, &mut send),
                GuardProgress::Waiting
            );
            assert_eq!(
                guard.poll(&request, effect, 77, 3, &mut send),
                GuardProgress::Authorized
            );
        }
        assert_eq!(transport_ids.len(), 2);
        assert_ne!(transport_ids[0], transport_ids[1]);
    }
    #[test]
    fn verified_plan_with_invalid_settings_does_not_dispatch() {
        let request: ProviderRequest = serde_json::from_value(json!({"provider_sequence":1,"operation":"resource_plan","version":1,"transition_id":"transition-1","operation_id":"op-1","target":{"kind":"validation","host_epoch":"epoch-1","validation_id":"validation-1","generation":1},"phase":"stream.prepare","settings_revision":"revision","settings":{},"intent":null,"reason":null,"requested_video":null,"consumer_requirements":{"execution_domain":"desktop","capture_providers":["capture"],"selector_schemas":["selector/1"]},"remaining_ms":100,"plan_revision":null,"admission_id":null,"approved_plan":null})).unwrap();
        let verify = PendingVerification::from_request(LIFECYCLE_CALLER, &request, 0).unwrap();
        let mut reply = Value::Null;
        let mut calls = VecDeque::from([0, 1, 2]);
        let mut send = |command| match (calls.pop_front().unwrap(), command) {
            (0, Command::Request { payload, .. }) => {
                reply = payload;
                Ok(Response::Accepted { id: 1 })
            }
            (1, Command::TakeResult { .. }) => {
                reply["status"] = "succeeded".into();
                Ok(Response::Result {
                    payload: reply.clone(),
                })
            }
            (2, Command::ReleaseResult { .. }) => Ok(Response::Ok),
            _ => panic!("unexpected native or state call"),
        };
        let phase = PendingPhase::Verify {
            request: Box::new(request),
            verification: Box::new(verify),
        };
        let phase = match advance_phase(phase, 77, 1, &mut send) {
            Ok(phase) => phase,
            Err(_) => panic!("unexpected completion"),
        };
        let phase = match advance_phase(phase, 77, 2, &mut send) {
            Ok(phase) => phase,
            Err(_) => panic!("unexpected completion"),
        };
        assert!(
            matches!(advance_phase(phase, 77, 3, &mut send),Err(response) if response["status"]=="rejected")
        );
    }
    #[test]
    fn action_endpoints_require_the_installed_actions_caller() {
        let payload = json!({"method":"action_execute","interface_major":1,"interface_minor":0,"arguments":{}});
        assert!(
            matches!(dispatch("untrusted",&payload,0,100),Dispatch::Immediate(response) if response["reason"]=="unauthorized_caller")
        );
        assert!(
            matches!(dispatch(crate::action_provider::ACTION_CALLER,&payload,0,100),Dispatch::Immediate(response) if response["reason"]=="invalid_request")
        );
        let target:extension_api::ActionTarget=serde_json::from_value(json!({"kind":"stream","host_epoch":"e","session_id":"s","stream_id":"x","expected_generation":4})).unwrap();
        assert!(matches!(
            action_lifecycle_target(&target),
            Ok(LifecycleTarget::Stream { generation: 4, .. })
        ));
    }
    #[test]
    fn action_planner_and_dispatch_remove_exact_owned_virtual_reference() {
        let epoch = "0123456789abcdef0123456789abcdef";
        let mut prepare = callback_request();
        if let LifecycleTarget::Stream { host_epoch, .. } = &mut prepare.target {
            *host_epoch = epoch.into();
        }
        let mut broker = FakeBroker::default();
        let prepared = broker.drive_effect(prepare.clone());
        assert_eq!(prepared["status"], "prepared");
        let target = json!({"kind":"stream","host_epoch":epoch,"session_id":"session-1","stream_id":"stream-1","expected_generation":7});
        broker.action_description = Some(
            json!({"status":"succeeded","provider":crate::descriptor::PROVIDER,"target":target,"session_target":{"kind":"session","host_epoch":epoch,"session_id":"session-1","generation":1},"execution_domain":"desktop","settings_revision":"frozen-1","settings":{},"streams":[{"target":target,"lifecycle_target":prepare.target,"phase":"active","candidate":prepared["candidate"],"consumers_retired":false}],"obligations":prepared["obligations"],"observation_obligations":prepared["obligations"],"admitted_plans":[{"admission_id":"admission-1","target":prepare.target,"phase":"stream.prepare","plan":prepare.approved_plan}],"plans":[],"mutation_domains":{"provider_session:abcdef":{"revision":2,"borrowers":{"stream-1":7}}}}),
        );
        let request:crate::action_provider::PlanRequest=serde_json::from_value(json!({"version":1,"operation_id":format!("{epoch}:1"),"action_id":crate::actions::REMOVE_OWNED,"target":target,"arguments":{},"expected_settings_revision":null})).unwrap();
        let planner = crate::action_provider::ActionPlanner::new(
            crate::action_provider::ACTION_CALLER,
            request.clone(),
            77,
            0,
            5000,
        )
        .unwrap();
        let mut phase = PendingPhase::ActionPlan {
            planner: Box::new(planner),
            request: Box::new(request.clone()),
        };
        let mut plan = None;
        for tick in 1..500 {
            match advance_phase(phase, 77, tick, &mut |c| broker.send(c)) {
                Ok(next) => phase = next,
                Err(result) => {
                    assert_eq!(result["status"], "planned", "{result}");
                    plan = Some(result["plan"].clone());
                    break;
                }
            }
        }
        let plan = plan.expect("planner did not finish");
        assert_eq!(
            plan["constraints"]["selected_settings_revision"],
            "frozen-1"
        );
        let plan: extension_api::ResourcePlan = serde_json::from_value(plan).unwrap();
        let execute = crate::action_provider::ExecuteRequest {
            version: 1,
            operation_id: request.operation_id.clone(),
            action_id: request.action_id.clone(),
            target: request.target.clone(),
            arguments: request.arguments.clone(),
            expected_settings_revision: None,
            plan_digest: crate::action_provider::plan_digest(&plan).unwrap(),
            plan,
            permit: "permit-1".into(),
        };
        let mut phase = start_action_execute(Box::new(execute.clone()), 77, 0, 5000).unwrap();
        let mut outcome = Value::Null;
        for tick in 1..500 {
            match advance_phase(phase, 77, tick, &mut |c| broker.send(c)) {
                Ok(next) => phase = next,
                Err(result) => {
                    outcome = result;
                    break;
                }
            }
        }
        assert_eq!(outcome["status"], "succeeded", "{outcome}");
        assert!(
            broker
                .effects
                .ends_with(&["release_borrow".into(), "remove".into()])
        );
        let original_effects = broker.effects.clone();
        // A new dispatcher instance after restart must replay the durable terminal
        // receipt rather than invoke the native backend for the same operation.
        let mut restarted = start_action_execute(Box::new(execute), 78, 0, 5000).unwrap();
        let mut replay = Value::Null;
        for tick in 1..500 {
            match advance_phase(restarted, 78, tick, &mut |c| broker.send(c)) {
                Ok(next) => restarted = next,
                Err(result) => {
                    replay = result;
                    break;
                }
            }
        }
        assert_eq!(replay["status"], "succeeded", "{replay}");
        assert_eq!(broker.effects, original_effects);
    }
}
