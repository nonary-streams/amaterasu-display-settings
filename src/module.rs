//! Versioned display-policy participant. Native controls are performed by the
//! coordinator-selected resource owner after admission.
use crate::coordinator::{PendingVerification, Verification};
use amaterasu_module_sdk::{
    ApiFieldKind as Kind, ApiMethod, ApiPrivilege, ApiSchema, Command, ManagedModule, ModuleResult,
    Response, RuntimeClient,
    extension_api::{self, ProviderOperation, ProviderRequest},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Instant};
const SERVICE: &str = crate::descriptor::SERVICE;
const REGISTRY_CALLER: &str = "amaterasu.extension-registry";
const LIFECYCLE_CALLER: &str = "amaterasu.session-lifecycle";
const MAX_PENDING: usize = 32;
const REGISTERED_METHODS: &[&str] = &[
    "settings_validate",
    "resource_plan",
    "lifecycle_callback",
    "lifecycle_status",
];
pub struct DisplaySettingsModule {
    runtime: RuntimeClient,
    clock: Instant,
    pending: Vec<PendingRequest>,
}
struct PendingRequest {
    request_id: u64,
    request: ProviderRequest,
    verification: PendingVerification,
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
        "resource_plan" | "lifecycle_callback" => schema(
            &provider_fields,
            &[
                ("dependency_inputs", Kind::Array),
                ("control_results", Kind::Array),
            ],
        ),
        "lifecycle_status" => schema(
            &[
                ("provider_sequence", Kind::Integer),
                ("operation_id", Kind::String),
                ("transition_id", Kind::String),
                ("receipt_id", Kind::String),
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
                ("outputs", Kind::Array),
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
            interface_major: 2,
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
        || object.get("interface_major")?.as_u64()? != 2
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
}
fn dispatch(caller: &str, payload: &Value, now_ms: u64, remaining_ms: u64) -> Dispatch {
    let Some((method, args)) = arguments(payload) else {
        return Dispatch::Immediate(rejected("invalid_request"));
    };
    if caller != LIFECYCLE_CALLER {
        return Dispatch::Immediate(rejected("unauthorized_caller"));
    }
    if method == "lifecycle_status" {
        return Dispatch::Immediate(recovery("legacy_owner_recovery_required"));
    }
    let operation = match method {
        "resource_plan" => ProviderOperation::ResourcePlan,
        "lifecycle_callback" => ProviderOperation::LifecycleCallback,
        _ => return Dispatch::Immediate(rejected("unknown_method")),
    };
    let Ok(request) = serde_json::from_value::<ProviderRequest>(args.clone()) else {
        return Dispatch::Immediate(rejected("invalid_request"));
    };
    if request.version != extension_api::COMPOSITION_VERSION {
        return Dispatch::Immediate(recovery("legacy_owner_recovery_required"));
    }
    if request.operation != operation || extension_api::validate_provider_request(&request).is_err()
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
fn advance_request(
    item: &mut PendingRequest,
    now_ms: u64,
    send: &mut impl FnMut(Command) -> ModuleResult<Response>,
) -> Option<Value> {
    match item.verification.poll(now_ms, send) {
        Verification::Pending => None,
        Verification::Rejected => Some(rejected("coordinator_verification_rejected")),
        Verification::Unknown => Some(recovery("coordinator_verification_unknown")),
        Verification::Verified => {
            if !matches!(
                send(Command::CheckRequest {
                    request: item.request_id
                }),
                Ok(Response::Ok)
            ) {
                return Some(recovery("request_ended_before_response"));
            }
            let result = match item.request.operation {
                ProviderOperation::ResourcePlan => {
                    crate::composed_plan::plan_composed(&item.request)
                        .map(|plan| extension_api::ProviderResponse::Planned { plan })
                }
                ProviderOperation::LifecycleCallback => {
                    crate::composition_callback::composition_callback(&item.request)
                }
                ProviderOperation::ResourceFinalizePlan => Err("unsupported_operation"),
            };
            Some(match result {
                Ok(response) => serde_json::to_value(response)
                    .unwrap_or_else(|_| recovery("invalid_composition_response")),
                Err(reason) => rejected(reason),
            })
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
        match advance_request(&mut item, now, &mut |command| self.runtime.send(command)) {
            Some(response) => self.complete(item.request_id, response),
            None => {
                self.pending.push(item);
                Ok(())
            }
        }
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
                    Dispatch::Verify(request, verification) if self.pending.len() < MAX_PENDING => {
                        self.pending.push(PendingRequest {
                            request_id: id,
                            request: *request,
                            verification: *verification,
                        });
                        Ok(())
                    }
                    Dispatch::Verify(_, _) => self.complete(id, rejected("provider_busy")),
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
    #[test]
    fn validates_registry_settings_and_rejects_removed_methods() {
        let values =
            amaterasu_configuration_schema::defaults(&crate::settings_schema::definitions())
                .unwrap();
        let payload = json!({"method":"settings_validate","interface_major":2,"interface_minor":0,"arguments":{"values":values}});
        assert_eq!(
            validate_request(REGISTRY_CALLER, payload.clone())["valid"],
            true
        );
        assert_eq!(validate_request("untrusted", payload)["valid"], false);
        for method in [
            "action_plan",
            "action_execute",
            "action_status",
            "binding_validate",
        ] {
            let payload =
                json!({"method":method,"interface_major":2,"interface_minor":0,"arguments":{}});
            assert!(
                matches!(dispatch(LIFECYCLE_CALLER, &payload, 0, 100), Dispatch::Immediate(response) if response["reason"] == "unknown_method")
            );
            assert!(!REGISTERED_METHODS.contains(&method));
        }
    }
    #[test]
    fn status_fences_legacy_receipts() {
        let payload = json!({"method":"lifecycle_status","interface_major":2,"interface_minor":0,"arguments":{}});
        assert!(
            matches!(dispatch(LIFECYCLE_CALLER, &payload, 0, 100), Dispatch::Immediate(response) if response["reason"] == "legacy_owner_recovery_required")
        );
    }
    #[test]
    fn legacy_requests_are_fenced_before_admission() {
        let request = json!({"provider_sequence":1,"operation":"resource_plan","version":1,"transition_id":"t","operation_id":"o","target":{"kind":"session","host_epoch":"epoch","session_id":"session","generation":1},"phase":"session.prepare","settings_revision":"1","settings":{},"intent":"initial","reason":null,"requested_video":null,"consumer_requirements":{"execution_domain":"desktop","capture_providers":[],"selector_schemas":[]},"remaining_ms":100,"plan_revision":null,"admission_id":null,"approved_plan":null});
        let payload = json!({"method":"resource_plan","interface_major":2,"interface_minor":0,"arguments":request});
        assert!(
            matches!(dispatch(LIFECYCLE_CALLER, &payload, 0, 100), Dispatch::Immediate(response) if response["reason"] == "legacy_owner_recovery_required")
        );
    }
    #[test]
    fn checked_in_approvals_match_registered_methods() {
        let actual: Value =
            serde_json::from_str(include_str!("../examples/lifecycle-api-approvals.json")).unwrap();
        let expected: Vec<Value> = REGISTERED_METHODS
            .iter()
            .map(|name| {
                let Command::RegisterApi { method } = registration(name) else {
                    unreachable!()
                };
                let callers = if *name == "settings_validate" {
                    vec![REGISTRY_CALLER]
                } else {
                    vec![LIFECYCLE_CALLER]
                };
                json!({"provider":crate::descriptor::PROVIDER,"callers":callers,"method":method})
            })
            .collect();
        assert_eq!(actual, json!({"api_methods":expected}));
    }
}
