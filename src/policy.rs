//! Pure display intent resolution. A resolved intent is not evidence that a
//! provider has applied it, or that a display advertises the requested mode.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolution {
    pub width: u32,
    pub height: u32,
}

impl Resolution {
    pub fn validate(self) -> Result<Self, PolicyError> {
        if self.width == 0 || self.height == 0 {
            return Err(PolicyError::InvalidResolution);
        }
        Ok(self)
    }
}

/// Exact refresh in hertz. Both components must be nonzero for a display mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshRate {
    pub numerator: u32,
    pub denominator: u32,
}

impl RefreshRate {
    pub fn validate(self) -> Result<Self, PolicyError> {
        if self.numerator == 0 || self.denominator == 0 {
            return Err(PolicyError::InvalidRefreshRate);
        }
        Ok(self)
    }

    fn equivalent(self, other: Self) -> bool {
        u64::from(self.numerator) * u64::from(other.denominator)
            == u64::from(other.numerator) * u64::from(self.denominator)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayMode {
    pub resolution: Resolution,
    pub refresh: RefreshRate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionPolicy {
    Preserve,
    Client,
    Manual(Resolution),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshPolicy {
    Preserve,
    Client,
    Manual(RefreshRate),
    HighestAvailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HdrPolicy {
    Preserve,
    FollowClient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HdrRequestOverride {
    FollowClient,
    ForceOn,
    ForceOff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalingPolicy {
    Preserve,
    Automatic,
    Percent(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutPolicy {
    Preserve,
    Exclusive,
    Extended,
    ExtendedPrimary,
    ExtendedIsolated,
    ExtendedPrimaryIsolated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayPolicy {
    pub resolution: ResolutionPolicy,
    pub refresh: RefreshPolicy,
    pub hdr: HdrPolicy,
    pub hdr_request_override: HdrRequestOverride,
    pub scaling: ScalingPolicy,
    pub layout: LayoutPolicy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientDisplayRequest {
    pub resolution: Option<Resolution>,
    pub refresh: Option<RefreshRate>,
    pub hdr: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedDisplayPolicy {
    pub resolution: Option<Resolution>,
    pub refresh: Option<RefreshRate>,
    pub hdr: Option<bool>,
    /// None preserves the provider's existing scaling.
    pub scale_percent: Option<u16>,
    pub layout: LayoutPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    InvalidResolution,
    InvalidRefreshRate,
    InvalidScale,
    MissingClientResolution,
    MissingClientRefresh,
    MissingResolutionForHighestRefresh,
    NoMatchingMode,
    UnsupportedHdr,
    UnsupportedScaling,
    UnsupportedLayout,
}

/// Explicit provider capabilities. A caller must obtain these from the actual
/// provider; policy resolution alone cannot establish platform support.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderCapabilities {
    pub hdr: bool,
    pub scaling: bool,
    pub layout: bool,
}

const SUPPORTED_SCALES: [u16; 12] = [100, 125, 150, 175, 200, 225, 250, 300, 350, 400, 450, 500];

impl ScalingPolicy {
    /// Validate a configured scale against the portable preset set.
    pub fn validate(self) -> Result<Self, PolicyError> {
        if let Self::Percent(percent) = self
            && !SUPPORTED_SCALES.contains(&percent)
        {
            return Err(PolicyError::InvalidScale);
        }
        Ok(self)
    }
}

/// Resolve requested fields. `available_modes` is only consulted for highest
/// refresh; an empty or incomplete catalog cannot establish mode support.
pub fn resolve_policy(
    policy: DisplayPolicy,
    client: ClientDisplayRequest,
    available_modes: &[DisplayMode],
    capabilities: ProviderCapabilities,
) -> Result<ResolvedDisplayPolicy, PolicyError> {
    let resolution = match policy.resolution {
        ResolutionPolicy::Preserve => None,
        ResolutionPolicy::Client => Some(
            client
                .resolution
                .ok_or(PolicyError::MissingClientResolution)?
                .validate()?,
        ),
        ResolutionPolicy::Manual(value) => Some(value.validate()?),
    };
    let refresh = match policy.refresh {
        RefreshPolicy::Preserve => None,
        RefreshPolicy::Client => Some(
            client
                .refresh
                .ok_or(PolicyError::MissingClientRefresh)?
                .validate()?,
        ),
        RefreshPolicy::Manual(value) => Some(value.validate()?),
        RefreshPolicy::HighestAvailable => {
            let target = resolution.ok_or(PolicyError::MissingResolutionForHighestRefresh)?;
            let mut highest: Option<RefreshRate> = None;
            for mode in available_modes
                .iter()
                .filter(|mode| mode.resolution == target)
            {
                let candidate = mode.refresh.validate()?;
                if highest.is_none_or(|current| {
                    u64::from(candidate.numerator) * u64::from(current.denominator)
                        > u64::from(current.numerator) * u64::from(candidate.denominator)
                }) {
                    highest = Some(candidate);
                }
            }
            Some(highest.ok_or(PolicyError::NoMatchingMode)?)
        }
    };
    let hdr = match policy.hdr {
        HdrPolicy::Preserve => None,
        HdrPolicy::FollowClient => {
            if !capabilities.hdr {
                return Err(PolicyError::UnsupportedHdr);
            }
            Some(match policy.hdr_request_override {
                HdrRequestOverride::FollowClient => client.hdr,
                HdrRequestOverride::ForceOn => true,
                HdrRequestOverride::ForceOff => false,
            })
        }
    };
    let scale_percent = match policy.scaling.validate()? {
        ScalingPolicy::Preserve => None,
        ScalingPolicy::Automatic => {
            if !capabilities.scaling {
                return Err(PolicyError::UnsupportedScaling);
            }
            let size = resolution.ok_or(PolicyError::InvalidResolution)?;
            let desired = u64::from(size.width.min(size.height)) * 100;
            Some(
                *SUPPORTED_SCALES
                    .iter()
                    .min_by_key(|&&scale| (u64::from(scale) * 864).abs_diff(desired))
                    .expect("scale catalog is nonempty"),
            )
        }
        ScalingPolicy::Percent(percent) => {
            if !capabilities.scaling {
                return Err(PolicyError::UnsupportedScaling);
            }
            Some(percent)
        }
    };
    if policy.layout != LayoutPolicy::Preserve && !capabilities.layout {
        return Err(PolicyError::UnsupportedLayout);
    }
    Ok(ResolvedDisplayPolicy {
        resolution,
        refresh,
        hdr,
        scale_percent,
        layout: policy.layout,
    })
}

/// Check an exact complete mode against an authoritative provider catalog.
/// An empty catalog is treated as no match, not as unrestricted support.
pub fn mode_is_advertised(
    mode: DisplayMode,
    available_modes: &[DisplayMode],
) -> Result<bool, PolicyError> {
    mode.resolution.validate()?;
    mode.refresh.validate()?;
    Ok(available_modes.iter().any(|candidate| {
        candidate.resolution == mode.resolution
            && candidate.refresh.validate().is_ok()
            && candidate.refresh.equivalent(mode.refresh)
    }))
}
