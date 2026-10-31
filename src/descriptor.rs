//! Metadata for generic extension editors. Not installable until operator approval.
use amaterasu_configuration_schema::{Definition, Fields};
use amaterasu_module_sdk::extension_api::{
    ActionDescriptor, ApplyPolicy, ExecutionClass, ExtensionDescriptor, MethodRef,
    OptionDescriptor, SettingScope, TargetKind,
};

pub const PROVIDER: &str = "nonary.display-settings";
pub const SERVICE: &str = "nonary.display-settings/1";

/// Descriptor metadata; registration and installed approvals determine use.
pub fn descriptor() -> ExtensionDescriptor {
    let options = crate::settings_schema::definitions()
        .into_iter()
        .map(|(id, definition)| {
            let label = id.replace('_', " ");
            OptionDescriptor {
                id,
                label,
                help: "Applied on a future session after provider support is verified.".into(),
                definition,
                presentation: None,
                allowed_scopes: vec![
                    SettingScope::Host,
                    SettingScope::Application,
                    SettingScope::PairedClient,
                    SettingScope::Session,
                ],
                apply_policy: ApplyPolicy::NextSession,
                required_capabilities: vec![],
            }
        })
        .collect();
    ExtensionDescriptor {
        provider: PROVIDER.into(),
        revision: 1,
        options,
        actions: vec![action_descriptor(crate::actions::REMOVE_OWNED)],
        capabilities: vec![],
        settings_validate: MethodRef {
            service: SERVICE.into(),
            method: "settings_validate".into(),
            interface_major: 1,
            interface_minor: 0,
            schema_revision: 1,
        },
    }
}

pub fn action_descriptors() -> Vec<ActionDescriptor> {
    [
        crate::actions::REMOVE_OWNED,
        crate::actions::RECREATE_OWNED,
        crate::actions::SET_MODE,
    ]
    .into_iter()
    .map(action_descriptor)
    .collect()
}

fn action_descriptor(id: &str) -> ActionDescriptor {
    let method = |method: &str| MethodRef {
        service: SERVICE.into(),
        method: method.into(),
        interface_major: 1,
        interface_minor: 0,
        schema_revision: 1,
    };
    let arguments: Fields = if id == crate::actions::SET_MODE {
        [
            "width",
            "height",
            "refresh_numerator",
            "refresh_denominator",
        ]
        .into_iter()
        .map(|key| {
            (
                key.to_owned(),
                Definition::Integer {
                    default: 1,
                    minimum: Some(1),
                    maximum: Some(u32::MAX.into()),
                },
            )
        })
        .collect()
    } else {
        Fields::new()
    };
    ActionDescriptor {
        id: id.into(),
        label: id.rsplit('/').next().unwrap_or(id).replace('-', " "),
        description: "Changes a display owned by the selected session after its consumers retire."
            .into(),
        execution: ExecutionClass::SessionMutation,
        arguments,
        allowed_targets: vec![TargetKind::Session, TargetKind::Stream],
        required_capabilities: vec![],
        plan: Some(method("action_plan")),
        execute: method("action_execute"),
        status: Some(method("action_status")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn descriptor_uses_public_contract_and_complete_settings() {
        let descriptor = super::descriptor();
        amaterasu_module_sdk::extension_api::validate_descriptor(&descriptor).unwrap();
        assert_eq!(
            descriptor.options.len(),
            crate::settings_schema::definitions().len()
        );
        assert_eq!(descriptor.actions.len(), 1);
        assert_eq!(descriptor.actions[0].id, crate::actions::REMOVE_OWNED);
        assert_eq!(super::action_descriptors().len(), 3);
    }
}
