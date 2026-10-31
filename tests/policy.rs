use amaterasu_display_settings::policy::*;
use std::time::Duration;

fn resolution(width: u32, height: u32) -> Resolution {
    Resolution { width, height }
}

fn rate(numerator: u32, denominator: u32) -> RefreshRate {
    RefreshRate {
        numerator,
        denominator,
    }
}

fn base() -> DisplayPolicy {
    DisplayPolicy {
        resolution: ResolutionPolicy::Client,
        refresh: RefreshPolicy::Client,
        hdr: HdrPolicy::Preserve,
        hdr_request_override: HdrRequestOverride::FollowClient,
        scaling: ScalingPolicy::Preserve,
        layout: LayoutPolicy::Preserve,
        retention: RetentionPolicy::UntilSessionEnds,
    }
}

fn client() -> ClientDisplayRequest {
    ClientDisplayRequest {
        resolution: Some(resolution(1920, 1080)),
        refresh: Some(rate(60000, 1001)),
        hdr: true,
    }
}

#[test]
fn client_mode_is_selected_exactly_and_missing_or_invalid_values_fail() {
    let resolved = resolve_policy(base(), client(), &[], ProviderCapabilities::default()).unwrap();
    assert_eq!(resolved.resolution, Some(resolution(1920, 1080)));
    assert_eq!(resolved.refresh, Some(rate(60000, 1001)));
    assert_eq!(
        resolve_policy(
            base(),
            ClientDisplayRequest::default(),
            &[],
            ProviderCapabilities::default()
        ),
        Err(PolicyError::MissingClientResolution)
    );
    let mut request = client();
    request.refresh = Some(rate(60, 0));
    assert_eq!(
        resolve_policy(base(), request, &[], ProviderCapabilities::default()),
        Err(PolicyError::InvalidRefreshRate)
    );
    request = client();
    request.resolution = Some(resolution(0, 1080));
    assert_eq!(
        resolve_policy(base(), request, &[], ProviderCapabilities::default()),
        Err(PolicyError::InvalidResolution)
    );
}

#[test]
fn highest_refresh_is_selected_only_with_matching_dimensions() {
    let mut policy = base();
    policy.resolution = ResolutionPolicy::Manual(resolution(1920, 1080));
    policy.refresh = RefreshPolicy::HighestAvailable;
    let modes = [
        DisplayMode {
            resolution: resolution(1920, 1080),
            refresh: rate(60000, 1001),
        },
        DisplayMode {
            resolution: resolution(1920, 1080),
            refresh: rate(60, 1),
        },
        DisplayMode {
            resolution: resolution(3840, 2160),
            refresh: rate(144, 1),
        },
    ];
    assert_eq!(
        resolve_policy(policy, client(), &modes, ProviderCapabilities::default())
            .unwrap()
            .refresh,
        Some(rate(60, 1))
    );
    assert_eq!(
        resolve_policy(policy, client(), &[], ProviderCapabilities::default()),
        Err(PolicyError::NoMatchingMode)
    );
    policy.resolution = ResolutionPolicy::Preserve;
    assert_eq!(
        resolve_policy(policy, client(), &modes, ProviderCapabilities::default()),
        Err(PolicyError::MissingResolutionForHighestRefresh)
    );
}

#[test]
fn exact_catalog_matching_accepts_equivalent_rationals_only() {
    let mode = DisplayMode {
        resolution: resolution(1920, 1080),
        refresh: rate(60, 1),
    };
    let equivalent = DisplayMode {
        refresh: rate(120, 2),
        ..mode
    };
    let fractional = DisplayMode {
        refresh: rate(60000, 1001),
        ..mode
    };
    assert_eq!(mode_is_advertised(mode, &[equivalent]), Ok(true));
    assert_eq!(mode_is_advertised(mode, &[fractional]), Ok(false));
    assert_eq!(mode_is_advertised(mode, &[]), Ok(false));
}

#[test]
fn provider_capabilities_fail_closed_and_hdr_override_is_explicit() {
    let mut policy = base();
    policy.hdr = HdrPolicy::FollowClient;
    policy.hdr_request_override = HdrRequestOverride::ForceOff;
    assert_eq!(
        resolve_policy(policy, client(), &[], ProviderCapabilities::default()),
        Err(PolicyError::UnsupportedHdr)
    );
    let capabilities = ProviderCapabilities {
        hdr: true,
        ..ProviderCapabilities::default()
    };
    assert_eq!(
        resolve_policy(policy, client(), &[], capabilities)
            .unwrap()
            .hdr,
        Some(false)
    );
    policy.hdr_request_override = HdrRequestOverride::ForceOn;
    assert_eq!(
        resolve_policy(
            policy,
            ClientDisplayRequest {
                hdr: false,
                ..client()
            },
            &[],
            capabilities
        )
        .unwrap()
        .hdr,
        Some(true)
    );
    policy.hdr = HdrPolicy::Preserve;
    assert_eq!(
        resolve_policy(policy, client(), &[], ProviderCapabilities::default())
            .unwrap()
            .hdr,
        None
    );
}

#[test]
fn scale_layout_and_retention_require_explicit_support() {
    let mut policy = base();
    policy.scaling = ScalingPolicy::Automatic;
    assert_eq!(
        resolve_policy(policy, client(), &[], ProviderCapabilities::default()),
        Err(PolicyError::UnsupportedScaling)
    );
    let mut capabilities = ProviderCapabilities {
        scaling: true,
        ..ProviderCapabilities::default()
    };
    assert_eq!(
        resolve_policy(policy, client(), &[], capabilities)
            .unwrap()
            .scale_percent,
        Some(125)
    );
    policy.scaling = ScalingPolicy::Percent(123);
    assert_eq!(
        resolve_policy(policy, client(), &[], capabilities),
        Err(PolicyError::InvalidScale)
    );
    policy.scaling = ScalingPolicy::Preserve;
    policy.layout = LayoutPolicy::ExtendedPrimaryIsolated;
    assert_eq!(
        resolve_policy(policy, client(), &[], capabilities),
        Err(PolicyError::UnsupportedLayout)
    );
    capabilities.layout = true;
    policy.retention = RetentionPolicy::AfterDisconnect(Duration::from_secs(30));
    assert_eq!(
        resolve_policy(policy, client(), &[], capabilities),
        Err(PolicyError::UnsupportedRetention)
    );
    capabilities.retention = true;
    assert_eq!(
        resolve_policy(policy, client(), &[], capabilities)
            .unwrap()
            .retention,
        policy.retention
    );
}
