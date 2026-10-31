//! Serializable display policy for a future session.
//!
//! Fields are fixed so the shared configuration schema can describe them.
//! Numeric values belonging to an inactive choice remain stored for later use;
//! they are validated even while inactive, and affect policy only when selected.
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::policy::{
    DisplayPolicy, HdrPolicy, HdrRequestOverride, LayoutPolicy, RefreshPolicy, RefreshRate,
    Resolution, ResolutionPolicy, RetentionPolicy, ScalingPolicy,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DisplaySettings {
    pub enabled: bool,
    pub resolution: ResolutionSetting,
    pub width: u32,
    pub height: u32,
    pub refresh: RefreshSetting,
    pub refresh_numerator: u32,
    pub refresh_denominator: u32,
    pub hdr: HdrSetting,
    pub hdr_request_override: HdrOverrideSetting,
    pub scaling: ScalingSetting,
    pub scale_percent: u16,
    pub layout: LayoutSetting,
    pub retention: RetentionSetting,
    pub retention_seconds: u32,
    pub keepalive_while_paused: bool,
    pub enforce_while_paused: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionSetting {
    #[default]
    Preserve,
    Client,
    Manual,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RefreshSetting {
    #[default]
    Preserve,
    Client,
    Manual,
    HighestAvailable,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HdrSetting {
    #[default]
    Preserve,
    FollowClient,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HdrOverrideSetting {
    #[default]
    FollowClient,
    ForceOn,
    ForceOff,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScalingSetting {
    #[default]
    Preserve,
    Automatic,
    Percent,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LayoutSetting {
    #[default]
    Preserve,
    Exclusive,
    Extended,
    ExtendedPrimary,
    ExtendedIsolated,
    ExtendedPrimaryIsolated,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetentionSetting {
    #[default]
    UntilSessionEnds,
    AfterDisconnect,
    UntilExplicitRelease,
}

impl Default for DisplaySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            resolution: ResolutionSetting::Preserve,
            width: 1920,
            height: 1080,
            refresh: RefreshSetting::Preserve,
            refresh_numerator: 60,
            refresh_denominator: 1,
            hdr: HdrSetting::Preserve,
            hdr_request_override: HdrOverrideSetting::FollowClient,
            scaling: ScalingSetting::Preserve,
            scale_percent: 100,
            layout: LayoutSetting::Preserve,
            retention: RetentionSetting::UntilSessionEnds,
            retention_seconds: 300,
            keepalive_while_paused: false,
            enforce_while_paused: false,
        }
    }
}

impl DisplaySettings {
    /// Validate settings before persistence and again before planning effects.
    pub fn to_policy(&self) -> Result<DisplayPolicy, &'static str> {
        let manual_resolution = Resolution {
            width: self.width,
            height: self.height,
        }
        .validate()
        .map_err(|_| "invalid_resolution")?;
        let manual_refresh = RefreshRate {
            numerator: self.refresh_numerator,
            denominator: self.refresh_denominator,
        }
        .validate()
        .map_err(|_| "invalid_refresh")?;
        let manual_scale = ScalingPolicy::Percent(self.scale_percent)
            .validate()
            .map_err(|_| "invalid_scale")?;
        let resolution = match self.resolution {
            ResolutionSetting::Preserve => ResolutionPolicy::Preserve,
            ResolutionSetting::Client => ResolutionPolicy::Client,
            ResolutionSetting::Manual => ResolutionPolicy::Manual(manual_resolution),
        };
        let refresh = match self.refresh {
            RefreshSetting::Preserve => RefreshPolicy::Preserve,
            RefreshSetting::Client => RefreshPolicy::Client,
            RefreshSetting::Manual => RefreshPolicy::Manual(manual_refresh),
            RefreshSetting::HighestAvailable => RefreshPolicy::HighestAvailable,
        };
        let scaling = match self.scaling {
            ScalingSetting::Preserve => ScalingPolicy::Preserve,
            ScalingSetting::Automatic => ScalingPolicy::Automatic,
            ScalingSetting::Percent => manual_scale,
        };
        Ok(DisplayPolicy {
            resolution,
            refresh,
            hdr: match self.hdr {
                HdrSetting::Preserve => HdrPolicy::Preserve,
                HdrSetting::FollowClient => HdrPolicy::FollowClient,
            },
            hdr_request_override: match self.hdr_request_override {
                HdrOverrideSetting::FollowClient => HdrRequestOverride::FollowClient,
                HdrOverrideSetting::ForceOn => HdrRequestOverride::ForceOn,
                HdrOverrideSetting::ForceOff => HdrRequestOverride::ForceOff,
            },
            scaling,
            layout: match self.layout {
                LayoutSetting::Preserve => LayoutPolicy::Preserve,
                LayoutSetting::Exclusive => LayoutPolicy::Exclusive,
                LayoutSetting::Extended => LayoutPolicy::Extended,
                LayoutSetting::ExtendedPrimary => LayoutPolicy::ExtendedPrimary,
                LayoutSetting::ExtendedIsolated => LayoutPolicy::ExtendedIsolated,
                LayoutSetting::ExtendedPrimaryIsolated => LayoutPolicy::ExtendedPrimaryIsolated,
            },
            retention: match self.retention {
                RetentionSetting::UntilSessionEnds => RetentionPolicy::UntilSessionEnds,
                RetentionSetting::AfterDisconnect => RetentionPolicy::AfterDisconnect(
                    Duration::from_secs(u64::from(self.retention_seconds)),
                ),
                RetentionSetting::UntilExplicitRelease => RetentionPolicy::UntilExplicitRelease,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_preserve_without_enforcement_and_round_trip() {
        let settings: DisplaySettings = serde_json::from_value(json!({})).unwrap();
        assert_eq!(settings, DisplaySettings::default());
        assert!(!settings.enforce_while_paused);
        assert_eq!(
            settings.to_policy().unwrap().retention,
            RetentionPolicy::UntilSessionEnds
        );
        assert_eq!(
            serde_json::from_value::<DisplaySettings>(serde_json::to_value(&settings).unwrap())
                .unwrap(),
            settings
        );
    }

    #[test]
    fn fixed_fields_validate_even_when_inactive_and_reject_unknown_values() {
        for value in [
            json!({"unexpected": true}),
            json!({"resolution":{"kind":"manual","width":1,"height":2}}),
            json!({"layout":"unknown"}),
        ] {
            assert!(serde_json::from_value::<DisplaySettings>(value).is_err());
        }
        for value in [
            json!({"width":0}),
            json!({"refresh_denominator":0}),
            json!({"scale_percent":123}),
        ] {
            assert!(
                serde_json::from_value::<DisplaySettings>(value)
                    .unwrap()
                    .to_policy()
                    .is_err()
            );
        }
    }

    #[test]
    fn selected_manual_fields_drive_policy() {
        let settings: DisplaySettings = serde_json::from_value(json!({"resolution":"manual","width":2560,"height":1440,"refresh":"manual","refresh_numerator":60000,"refresh_denominator":1001,"scaling":"percent","scale_percent":125,"retention":"after_disconnect","retention_seconds":60})).unwrap();
        let policy = settings.to_policy().unwrap();
        assert_eq!(
            policy.resolution,
            ResolutionPolicy::Manual(Resolution {
                width: 2560,
                height: 1440
            })
        );
        assert_eq!(
            policy.refresh,
            RefreshPolicy::Manual(RefreshRate {
                numerator: 60000,
                denominator: 1001
            })
        );
        assert_eq!(policy.scaling, ScalingPolicy::Percent(125));
        assert_eq!(
            policy.retention,
            RetentionPolicy::AfterDisconnect(Duration::from_secs(60))
        );
    }
}
