//! Action argument parsing. Authority and resource selection are supplied by
//! the coordinator after admission, never by these untrusted arguments.
use serde::Deserialize;
use serde_json::Value;

use crate::policy::{DisplayMode, RefreshRate, Resolution};

pub const REMOVE_OWNED: &str = "amaterasu.display-settings/remove-owned";
pub const RECREATE_OWNED: &str = "amaterasu.display-settings/recreate-owned";
pub const SET_MODE: &str = "amaterasu.display-settings/set-mode";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayAction {
    RemoveOwned,
    RecreateOwned,
    SetMode(DisplayMode),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArguments {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModeArguments {
    width: u32,
    height: u32,
    refresh_numerator: u32,
    refresh_denominator: u32,
}

/// Parse an intent only; this does not authorize or perform a display mutation.
pub fn parse_action(action_id: &str, arguments: Value) -> Result<DisplayAction, &'static str> {
    match action_id {
        REMOVE_OWNED | RECREATE_OWNED => {
            serde_json::from_value::<EmptyArguments>(arguments).map_err(|_| "invalid_arguments")?;
            Ok(if action_id == REMOVE_OWNED {
                DisplayAction::RemoveOwned
            } else {
                DisplayAction::RecreateOwned
            })
        }
        SET_MODE => {
            let args: ModeArguments =
                serde_json::from_value(arguments).map_err(|_| "invalid_arguments")?;
            let resolution = Resolution {
                width: args.width,
                height: args.height,
            }
            .validate()
            .map_err(|_| "invalid_resolution")?;
            let refresh = RefreshRate {
                numerator: args.refresh_numerator,
                denominator: args.refresh_denominator,
            }
            .validate()
            .map_err(|_| "invalid_refresh")?;
            Ok(DisplayAction::SetMode(DisplayMode {
                resolution,
                refresh,
            }))
        }
        _ => Err("unknown_action"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_known_actions_with_exact_arguments_are_accepted() {
        assert_eq!(
            parse_action(REMOVE_OWNED, json!({})),
            Ok(DisplayAction::RemoveOwned)
        );
        assert_eq!(
            parse_action(RECREATE_OWNED, json!({})),
            Ok(DisplayAction::RecreateOwned)
        );
        assert!(matches!(
            parse_action(
                SET_MODE,
                json!({"width":1920,"height":1080,"refresh_numerator":60000,"refresh_denominator":1001})
            ),
            Ok(DisplayAction::SetMode(_))
        ));
        assert_eq!(
            parse_action(REMOVE_OWNED, json!({"owner_id":"other"})),
            Err("invalid_arguments")
        );
        assert_eq!(
            parse_action(
                SET_MODE,
                json!({"width":1920,"height":1080,"refresh_numerator":60,"refresh_denominator":0})
            ),
            Err("invalid_refresh")
        );
        assert_eq!(parse_action("other", json!({})), Err("unknown_action"));
    }
}
