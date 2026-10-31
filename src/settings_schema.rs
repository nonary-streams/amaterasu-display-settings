//! Public schema for the fixed display settings object.
use amaterasu_configuration_schema::{Definition, Fields};

fn choices(default: &str, choices: &[&str]) -> Definition {
    Definition::Enum {
        default: default.into(),
        options: choices.iter().map(|value| (*value).into()).collect(),
    }
}
fn number(default: i64, min: i64, max: i64) -> Definition {
    Definition::Integer {
        default,
        minimum: Some(min),
        maximum: Some(max),
    }
}

/// Structural validation precedes `DisplaySettings::to_policy` cross-field checks.
pub fn definitions() -> Fields {
    [
        ("enabled", Definition::Boolean { default: false }),
        (
            "display_target",
            choices("virtual", &["virtual", "physical"]),
        ),
        (
            "physical_target",
            choices("automatic", &["automatic", "identifier"]),
        ),
        (
            "physical_display_id",
            Definition::String {
                default: String::new(),
                min_length: Some(0),
                max_length: Some(1024),
            },
        ),
        (
            "resolution",
            choices("preserve", &["preserve", "client", "manual"]),
        ),
        ("width", number(1920, 1, u32::MAX.into())),
        ("height", number(1080, 1, u32::MAX.into())),
        (
            "refresh",
            choices(
                "preserve",
                &["preserve", "client", "manual", "highest_available"],
            ),
        ),
        ("refresh_numerator", number(60, 1, u32::MAX.into())),
        ("refresh_denominator", number(1, 1, u32::MAX.into())),
        ("hdr", choices("preserve", &["preserve", "follow_client"])),
        (
            "hdr_request_override",
            choices("follow_client", &["follow_client", "force_on", "force_off"]),
        ),
        (
            "scaling",
            choices("preserve", &["preserve", "automatic", "percent"]),
        ),
        ("scale_percent", number(100, 0, u16::MAX.into())),
        (
            "layout",
            choices(
                "preserve",
                &[
                    "preserve",
                    "exclusive",
                    "extended",
                    "extended_primary",
                    "extended_isolated",
                    "extended_primary_isolated",
                ],
            ),
        ),
        (
            "retention",
            choices(
                "until_session_ends",
                &[
                    "until_session_ends",
                    "after_disconnect",
                    "until_explicit_release",
                ],
            ),
        ),
        ("retention_seconds", number(300, 0, u32::MAX.into())),
        (
            "keepalive_while_paused",
            Definition::Boolean { default: false },
        ),
        (
            "enforce_while_paused",
            Definition::Boolean { default: false },
        ),
    ]
    .into_iter()
    .map(|(key, definition)| (key.to_owned(), definition))
    .collect()
}

/// Validate the complete resolved settings before registry persistence.
pub fn validate(values: &amaterasu_configuration_schema::Values) -> Result<(), String> {
    let fields = definitions();
    if values.len() != fields.len() || fields.keys().any(|key| !values.contains_key(key)) {
        return Err("incomplete_settings".into());
    }
    amaterasu_configuration_schema::validate_values(&fields, values)?;
    let settings: crate::settings::DisplaySettings =
        serde_json::from_value(serde_json::to_value(values).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    settings.to_policy().map(|_| ()).map_err(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::DisplaySettings;

    #[test]
    fn public_defaults_match_the_runtime_settings() {
        let defaults = amaterasu_configuration_schema::defaults(&definitions()).unwrap();
        assert!(validate(&defaults).is_ok());
        assert_eq!(
            serde_json::to_value(defaults).unwrap(),
            serde_json::to_value(DisplaySettings::default()).unwrap()
        );
    }
    #[test]
    fn registry_validation_checks_sparse_scale_presets_and_complete_values() {
        let mut values = amaterasu_configuration_schema::defaults(&definitions()).unwrap();
        values.insert("scale_percent".into(), 123.into());
        assert_eq!(validate(&values).unwrap_err(), "invalid_scale");
        values.remove("scale_percent");
        assert!(validate(&values).is_err());
    }
}
