//! Metadata for generic extension editors. Not installable until operator approval.
use amaterasu_module_sdk::extension_api::{
    ApplyPolicy, ExtensionDescriptor, MethodRef, OptionDescriptor, SettingScope,
};

pub const PROVIDER: &str = "nonary.display-settings";
pub const SERVICE: &str = "nonary.display-settings/2";

/// Descriptor metadata; registration and installed approvals determine use.
pub fn descriptor() -> ExtensionDescriptor {
    let options = crate::settings_schema::definitions()
        .into_iter()
        .map(|(id, definition)| {
            let label = id.replace('_', " ");
            OptionDescriptor {
                id,
                label,
                help: "Applied on a future stream after provider support is verified.".into(),
                definition,
                presentation: None,
                allowed_scopes: vec![
                    SettingScope::Host,
                    SettingScope::Application,
                    SettingScope::PairedClient,
                    SettingScope::Session,
                ],
                apply_policy: ApplyPolicy::NextStream,
                required_capabilities: vec![],
            }
        })
        .collect();
    ExtensionDescriptor {
        provider: PROVIDER.into(),
        revision: 2,
        options,
        actions: vec![],
        capabilities: vec![],
        settings_validate: MethodRef {
            service: SERVICE.into(),
            method: "settings_validate".into(),
            interface_major: 2,
            interface_minor: 0,
            schema_revision: 1,
        },
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
        assert!(descriptor.actions.is_empty());
    }
}
