//! Native module entry point for validated extension settings.
use amaterasu_module_sdk::{
    ApiFieldKind, ApiMethod, ApiPrivilege, ApiSchema, Command, ManagedModule, ModuleResult,
    Response, RuntimeClient,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SERVICE: &str = "amaterasu.display-settings/1";
const REGISTRY_CALLER: &str = "amaterasu.extension-registry";

/// Only the settings validation endpoint is registered until lifecycle effect
/// admission and receipt retirement are implemented.
pub struct DisplaySettingsModule {
    runtime: RuntimeClient,
}

fn registration() -> Command {
    let schema = |required: &[(&str, ApiFieldKind)], optional: &[(&str, ApiFieldKind)]| ApiSchema {
        required: required
            .iter()
            .cloned()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
        optional: optional
            .iter()
            .cloned()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<BTreeMap<_, _>>(),
        allow_extra: false,
    };
    Command::RegisterApi {
        method: ApiMethod {
            service: SERVICE.into(),
            method: "settings_validate".into(),
            interface_major: 1,
            interface_minor: 0,
            request: schema(&[("values", ApiFieldKind::Object)], &[]),
            response: schema(
                &[
                    ("ok", ApiFieldKind::Boolean),
                    ("valid", ApiFieldKind::Boolean),
                ],
                &[("message", ApiFieldKind::String)],
            ),
            privilege: ApiPrivilege::User,
        },
    }
}

fn validate_request(caller: &str, payload: Value) -> Value {
    if caller != REGISTRY_CALLER {
        return json!({"ok":true,"valid":false,"message":"unauthorized caller"});
    }
    let Some(object) = payload.as_object() else {
        return json!({"ok":true,"valid":false,"message":"invalid request"});
    };
    if object.len() != 4
        || object.get("method").and_then(Value::as_str) != Some("settings_validate")
        || object.get("interface_major").and_then(Value::as_u64) != Some(1)
        || object.get("interface_minor").and_then(Value::as_u64) != Some(0)
    {
        return json!({"ok":true,"valid":false,"message":"invalid request"});
    }
    let Some(arguments) = object.get("arguments").and_then(Value::as_object) else {
        return json!({"ok":true,"valid":false,"message":"invalid request"});
    };
    if arguments.len() != 1 {
        return json!({"ok":true,"valid":false,"message":"invalid request"});
    }
    let values = arguments
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

impl ManagedModule for DisplaySettingsModule {
    fn start(runtime: RuntimeClient) -> ModuleResult<Self> {
        runtime.require_success(registration())?;
        Ok(Self { runtime })
    }

    fn tick(&mut self) -> ModuleResult<()> {
        match self.runtime.send(Command::Poll {})? {
            Response::Pending => Ok(()),
            Response::Request {
                id,
                caller,
                service,
                payload,
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
                let response = validate_request(&caller, payload);
                match self.runtime.send(Command::Complete {
                    request: id,
                    payload: response,
                })? {
                    Response::Ok => Ok(()),
                    Response::Error { code, .. }
                        if code == "request_ended" || code == "not_found" =>
                    {
                        Ok(())
                    }
                    _ => Err("settings validation completion failed".into()),
                }
            }
            _ => Err("settings validation polling failed".into()),
        }
    }
}

amaterasu_module_sdk::export_module!(DisplaySettingsModule);

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(
            validate_request(
                REGISTRY_CALLER,
                json!({"method":"settings_validate","interface_major":1,"interface_minor":0,"arguments":{"values":{}}})
            )["valid"],
            false
        );
        assert!(matches!(registration(), Command::RegisterApi { .. }));
    }
}
