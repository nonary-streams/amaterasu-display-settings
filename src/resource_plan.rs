//! Read-only resource planning for the independent display provider.
//!
//! A proposed plan does not authorize native effects. The coordinator must
//! admit it and recheck revisions before dispatching a lifecycle callback.
use crate::settings::{
    DisplaySettings, HdrOverrideSetting, HdrSetting, LayoutSetting, PhysicalTargetSetting,
    RefreshSetting, ResolutionSetting, RetentionSetting, ScalingSetting,
};
use crate::virtual_callback::VirtualObligation;
use crate::{descriptor, physical_display, virtual_display};
use amaterasu_module_sdk::{
    Command, ModuleResult, Response,
    extension_api::{
        self, BindingConstraint, ConsumerChange, LifecycleTarget, MethodRef, MutationDomainPlan,
        PlannedResource, ProviderOperation, ProviderRequest, ProviderResponse, ResourceAccess,
        ResourceObligation, ResourcePlan, VideoMode,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const COORDINATOR: &str = "amaterasu.session-lifecycle";
const CAPTURE: &str = "amaterasu.capture-pipewire/1";
const SELECTOR: &str = "amaterasu.kwin-wl-output/1";
const MAX_FAILURES: u8 = 3;

/// A caller must validate the broker-selected coordinator and planning target;
/// request fields alone are not authority to select or mutate a desktop.
pub struct Planner {
    request: ProviderRequest,
    selection: Selection,
    stage: Stage,
    exchange: Exchange,
    deadline_ms: u64,
    failures: u8,
    finished: Option<PlanProgress>,
    parent: Option<u64>,
    physical_domain: Option<(String, u64)>,
    session: Option<VerifiedSessionDisplay>,
    release: Option<(VirtualObligation, MutationDomainPlan, ResourceObligation)>,
}

/// Exact session-scoped obligation loaded from the authenticated provider
/// journal. The verifier must bind this target to the coordinator's stream.
pub struct VerifiedSessionDisplay {
    pub target: LifecycleTarget,
    pub obligation: VirtualObligation,
    observed_revision: Option<u64>,
}
impl VerifiedSessionDisplay {
    pub fn authenticate(
        target: LifecycleTarget,
        obligation: VirtualObligation,
        verify: impl FnOnce(&LifecycleTarget, &VirtualObligation) -> bool,
    ) -> Result<Self, &'static str> {
        if !matches!(target, LifecycleTarget::Session { .. })
            || obligation.reference_released
            || obligation.borrow.is_none()
            || !verify(&target, &obligation)
        {
            return Err("session_ownership_unverified");
        }
        Ok(Self {
            target,
            obligation,
            observed_revision: None,
        })
    }
}
/// Coordinator-admitted cleanup authority for a retained target journal entry.
pub struct ReleaseAuthority {
    pub domain: MutationDomainPlan,
    pub cleanup: ResourceObligation,
}
enum Selection {
    Virtual {
        identity: String,
        reference_id: String,
        mode: VideoMode,
        layout: Option<String>,
    },
    Physical,
}
#[derive(Clone, Copy)]
enum Stage {
    VirtualStatus,
    ValidateSessionBorrow,
    ValidateReleaseBorrow,
    PhysicalStatus,
    PhysicalSnapshot,
}
struct Exchange {
    command: Command,
    id: Option<u64>,
    result: Option<Value>,
    uncertain: bool,
}
#[derive(Clone, Debug, PartialEq)]
pub enum PlanProgress {
    Waiting,
    Complete(Box<ProviderResponse>),
    Unknown,
}

impl Planner {
    pub fn new(
        caller: &str,
        request: ProviderRequest,
        parent: Option<u64>,
        now_ms: u64,
        verify_target: impl FnOnce(&ProviderRequest) -> bool,
    ) -> Result<Self, &'static str> {
        if caller != COORDINATOR
            || request.operation != ProviderOperation::ResourcePlan
            || extension_api::validate_provider_request(&request).is_err()
            || !verify_target(&request)
        {
            return Err("unauthorized_or_invalid_request");
        }
        let settings_value =
            serde_json::to_value(&request.settings).map_err(|_| "invalid_settings")?;
        let settings: DisplaySettings =
            serde_json::from_value(settings_value.clone()).map_err(|_| "invalid_settings")?;
        if crate::settings_schema::validate(&request.settings).is_err()
            || settings.to_policy().is_err()
            || !settings.enabled
        {
            return Err("disabled_or_invalid_settings");
        }
        let target = settings_value
            .get("display_target")
            .and_then(Value::as_str)
            .unwrap_or("virtual");
        let timeout = request.remaining_ms.min(30_000);
        let (stage, selection, payload, service) = match target {
            "virtual" => {
                if !cfg!(target_os = "linux") {
                    return Err("virtual_platform_unsupported");
                }
                let (session, reference) = target_ids(&request.target)?;
                let identity = stable_uuid("display", session);
                let reference_id = format!("ref-{}", stable_hex("reference", &reference));
                virtual_display::DisplayReference {
                    identity: identity.clone(),
                    reference_id: reference_id.clone(),
                }
                .validate()?;
                if !request
                    .consumer_requirements
                    .capture_providers
                    .iter()
                    .any(|p| p == CAPTURE)
                    || !request
                        .consumer_requirements
                        .selector_schemas
                        .iter()
                        .any(|s| s == SELECTOR)
                {
                    return Err("capture_provider_unavailable");
                }
                let mode = resolve_mode(&request, &settings)?;
                if settings.keepalive_while_paused
                    || settings.enforce_while_paused
                    || settings.retention != RetentionSetting::UntilSessionEnds
                {
                    return Err("retention_policy_unsupported");
                }
                if settings.scaling != ScalingSetting::Preserve
                    || settings.hdr_request_override != HdrOverrideSetting::FollowClient
                {
                    return Err("display_policy_unsupported");
                }
                let layout = match settings.layout {
                    LayoutSetting::Preserve => None,
                    LayoutSetting::Exclusive => Some("exclusive".into()),
                    LayoutSetting::Extended => Some("extended".into()),
                    _ => return Err("layout_unsupported"),
                };
                let payload =
                    json!({"action":"status","identity":identity,"reference_id":reference_id});
                (
                    Stage::VirtualStatus,
                    Selection::Virtual {
                        identity,
                        reference_id,
                        mode,
                        layout,
                    },
                    payload,
                    virtual_display::SERVICE,
                )
            }
            "physical" => {
                if !cfg!(windows) {
                    return Err("physical_platform_unsupported");
                }
                (
                    Stage::PhysicalStatus,
                    Selection::Physical,
                    json!({"action":"status"}),
                    physical_display::SERVICE,
                )
            }
            _ => return Err("invalid_display_target"),
        };
        let exchange = make_exchange(service, payload, &request, "status", parent, timeout)?;
        Ok(Self {
            request,
            selection,
            stage,
            exchange,
            deadline_ms: now_ms.saturating_add(timeout),
            failures: 0,
            finished: None,
            parent,
            physical_domain: None,
            session: None,
            release: None,
        })
    }
    /// Plan release from the authenticated durable target and domain snapshot.
    pub fn new_release(
        caller: &str,
        request: ProviderRequest,
        prior: VirtualObligation,
        authority: ReleaseAuthority,
        parent: Option<u64>,
        now_ms: u64,
        verify: impl FnOnce(&ProviderRequest) -> bool,
    ) -> Result<Self, &'static str> {
        use extension_api::LifecyclePhase;
        let ReleaseAuthority { domain, cleanup } = authority;
        if !matches!(
            request.phase,
            LifecyclePhase::SessionRelease | LifecyclePhase::StreamRelease
        ) || caller != COORDINATOR
            || request.operation != ProviderOperation::ResourcePlan
            || extension_api::validate_provider_request(&request).is_err()
            || !verify(&request)
            || prior.reference_released
            || prior.provider_service != virtual_display::SERVICE
            || prior.borrow.is_none()
            || domain.domain != prior.domain_id
            || domain.access != ResourceAccess::Exclusive
        {
            return Err("release_ownership_unverified");
        }
        let (session, reference) = target_ids(&request.target)?;
        if prior.identity != stable_uuid("display", session)
            || prior.reference_id != format!("ref-{}", stable_hex("reference", &reference))
        {
            return Err("release_ownership_mismatch");
        }
        virtual_display::DisplayReference {
            identity: prior.identity.clone(),
            reference_id: prior.reference_id.clone(),
        }
        .validate()?;
        let borrow = prior.borrow.as_ref().ok_or("missing_release_borrow")?;
        let payload = json!({"action":"validate_borrow","identity":prior.identity,
            "reference_id":prior.reference_id,"borrow_id":borrow.borrow_id});
        let timeout = request.remaining_ms.min(30_000);
        let exchange = make_exchange(
            virtual_display::SERVICE,
            payload,
            &request,
            "validate-release",
            parent,
            timeout,
        )?;
        let selection = Selection::Virtual {
            identity: prior.identity.clone(),
            reference_id: prior.reference_id.clone(),
            mode: VideoMode {
                width: prior.width,
                height: prior.height,
                refresh_millihz: prior.refresh_millihz,
                hdr: prior.hdr_enabled,
            },
            layout: Some(prior.layout.clone()),
        };
        Ok(Self {
            request,
            selection,
            stage: Stage::ValidateReleaseBorrow,
            exchange,
            deadline_ms: now_ms.saturating_add(timeout),
            failures: 0,
            finished: None,
            parent,
            physical_domain: None,
            session: None,
            release: Some((prior, domain, cleanup)),
        })
    }
    /// Attach only a coordinator-bound journal record before the first poll.
    /// This validates its native borrow before observing the new reference.
    pub fn attach_session(
        &mut self,
        session: VerifiedSessionDisplay,
        now_ms: u64,
    ) -> Result<(), &'static str> {
        if !matches!(self.stage, Stage::VirtualStatus)
            || self.exchange.id.is_some()
            || self.exchange.result.is_some()
            || self.exchange.uncertain
        {
            return Err("planning_already_started");
        }
        let (stream_epoch, stream_session) = match &self.request.target {
            LifecycleTarget::Stream {
                host_epoch,
                session_id,
                ..
            } => (host_epoch, session_id),
            _ => return Err("not_stream_target"),
        };
        let (session_epoch, session_id) = match &session.target {
            LifecycleTarget::Session {
                host_epoch,
                session_id,
                ..
            } => (host_epoch, session_id),
            _ => return Err("invalid_session_target"),
        };
        let Selection::Virtual { identity, .. } = &self.selection else {
            return Err("invalid_selection");
        };
        let old = &session.obligation;
        let (_, session_reference) = target_ids(&session.target)?;
        let expected_reference = format!("ref-{}", stable_hex("reference", &session_reference));
        if stream_epoch != session_epoch
            || stream_session != session_id
            || old.identity != *identity
            || old.provider_service != virtual_display::SERVICE
            || old.reference_id != expected_reference
        {
            return Err("session_ownership_mismatch");
        }
        let borrow = old.borrow.as_ref().ok_or("missing_session_borrow")?;
        let payload = json!({"action":"validate_borrow","identity":old.identity,"reference_id":old.reference_id,"borrow_id":borrow.borrow_id});
        self.exchange = make_exchange(
            virtual_display::SERVICE,
            payload,
            &self.request,
            "validate-session",
            self.parent,
            self.deadline_ms.saturating_sub(now_ms),
        )?;
        self.session = Some(session);
        self.stage = Stage::ValidateSessionBorrow;
        Ok(())
    }
    /// Polls at most one broker command. Transport acceptance does not imply
    /// provider readiness or permission to execute a plan.
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> PlanProgress {
        if let Some(done) = &self.finished {
            return done.clone();
        }
        if now_ms >= self.deadline_ms || self.failures >= MAX_FAILURES {
            return self.finish(PlanProgress::Unknown);
        }
        if let Some(id) = self.exchange.id {
            if self.exchange.result.is_some() {
                match send(Command::ReleaseResult { request: id }) {
                    Ok(Response::Ok) => {
                        let value = self.exchange.result.take().expect("result");
                        self.consume(value, now_ms)
                    }
                    _ => {
                        self.failures += 1;
                        PlanProgress::Waiting
                    }
                }
            } else {
                match send(Command::TakeResult { request: id }) {
                    Ok(Response::Pending) => PlanProgress::Waiting,
                    Ok(Response::Result { payload }) => {
                        self.exchange.result = Some(payload);
                        PlanProgress::Waiting
                    }
                    _ => {
                        self.failures += 1;
                        PlanProgress::Waiting
                    }
                }
            }
        } else {
            match send(self.exchange.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.exchange.id = Some(id);
                    self.failures = 0;
                    PlanProgress::Waiting
                }
                Ok(Response::Error { .. }) if !self.exchange.uncertain => {
                    self.finish(rejected("provider_unavailable"))
                }
                _ => {
                    self.exchange.uncertain = true;
                    self.failures += 1;
                    PlanProgress::Waiting
                }
            }
        }
    }
    fn consume(&mut self, payload: Value, now_ms: u64) -> PlanProgress {
        match self.stage {
            Stage::ValidateReleaseBorrow => {
                let result = self.release_plan(&payload);
                match result {
                    Ok(plan) => self.finish(PlanProgress::Complete(Box::new(
                        ProviderResponse::Planned { plan },
                    ))),
                    Err(reason) => self.finish(rejected(reason)),
                }
            }
            Stage::ValidateSessionBorrow => {
                let Some(session) = self.session.as_mut() else {
                    return self.finish(rejected("session_ownership_unverified"));
                };
                let Some(saved) = session.obligation.borrow.as_ref() else {
                    return self.finish(rejected("session_ownership_unverified"));
                };
                let observed: Option<virtual_display::DisplayBorrow> = (|| {
                    Some(virtual_display::DisplayBorrow {
                        borrow_id: payload.get("borrow_id")?.as_str()?.to_owned(),
                        observed_output: serde_json::from_value(
                            payload.get("observed_output")?.clone(),
                        )
                        .ok()?,
                        mutation_domain: serde_json::from_value(
                            payload.get("mutation_domain")?.clone(),
                        )
                        .ok()?,
                    })
                })();
                let Some(current) = observed else {
                    return self.finish(rejected("session_borrow_unverified"));
                };
                if payload.get("ok").and_then(Value::as_bool) != Some(true)
                    || current.borrow_id != saved.borrow_id
                    || current.observed_output != saved.observed_output
                    || current.mutation_domain.id != saved.mutation_domain.id
                    || current.mutation_domain.revision < saved.mutation_domain.revision
                    || current.mutation_domain.borrowers != 1
                    || current.mutation_domain.pending_mutations != 0
                    || current.mutation_domain.scope != "provider_session"
                {
                    return self.finish(rejected("session_borrow_unverified"));
                }
                session.observed_revision = Some(current.mutation_domain.revision);
                let Selection::Virtual {
                    identity,
                    reference_id,
                    ..
                } = &self.selection
                else {
                    return self.finish(rejected("invalid_selection"));
                };
                let payload =
                    json!({"action":"status","identity":identity,"reference_id":reference_id});
                match make_exchange(
                    virtual_display::SERVICE,
                    payload,
                    &self.request,
                    "status",
                    self.parent,
                    self.deadline_ms.saturating_sub(now_ms),
                ) {
                    Ok(exchange) => {
                        self.exchange = exchange;
                        self.stage = Stage::VirtualStatus;
                        PlanProgress::Waiting
                    }
                    Err(_) => self.finish(rejected("provider_unavailable")),
                }
            }
            Stage::VirtualStatus => match self.virtual_plan(&payload) {
                Ok(plan) => self.finish(PlanProgress::Complete(Box::new(
                    ProviderResponse::Planned { plan },
                ))),
                Err(reason) => self.finish(rejected(reason)),
            },
            Stage::PhysicalStatus => {
                if payload.get("ok").and_then(Value::as_bool) != Some(true)
                    || payload.get("native_supported").and_then(Value::as_bool) != Some(true)
                    || payload.get("mutation_enabled").and_then(Value::as_bool) != Some(true)
                    || payload.get("state").and_then(Value::as_str) != Some("idle")
                {
                    return self.finish(rejected("physical_provider_unavailable"));
                }
                let Some(domain) = payload.get("mutation_domain") else {
                    return self.finish(rejected("physical_domain_unavailable"));
                };
                let Some(id) = domain.get("id").and_then(Value::as_str).filter(|v| {
                    v.starts_with("physical_provider_session:")
                        && v.len() <= 128
                        && v.bytes().all(|b| b.is_ascii_graphic())
                }) else {
                    return self.finish(rejected("physical_domain_unavailable"));
                };
                let Some(revision) = domain.get("revision").and_then(Value::as_u64) else {
                    return self.finish(rejected("physical_domain_unavailable"));
                };
                if domain.get("scope").and_then(Value::as_str) != Some("provider_lease_only")
                    || domain.get("active_leases").and_then(Value::as_u64) != Some(0)
                    || domain
                        .get("external_borrowers_known")
                        .and_then(Value::as_bool)
                        != Some(false)
                {
                    return self.finish(rejected("physical_domain_busy_or_unknown"));
                }
                self.physical_domain = Some((id.to_owned(), revision));
                let remaining = self.deadline_ms.saturating_sub(now_ms).min(30_000);
                match make_exchange(
                    physical_display::SERVICE,
                    json!({"action":"snapshot"}),
                    &self.request,
                    "snapshot",
                    self.parent,
                    remaining,
                ) {
                    Ok(exchange) => {
                        self.exchange = exchange;
                        self.stage = Stage::PhysicalSnapshot;
                        self.failures = 0;
                        PlanProgress::Waiting
                    }
                    Err(_) => self.finish(PlanProgress::Unknown),
                }
            }
            Stage::PhysicalSnapshot => {
                let snapshot: Option<physical_display::Configuration> = payload
                    .get("configuration")
                    .cloned()
                    .and_then(|v| serde_json::from_value(v).ok());
                let revision = payload.get("topology_revision").and_then(Value::as_str);
                if payload.get("ok").and_then(Value::as_bool) != Some(true)
                    || snapshot.as_ref().is_none_or(|s| s.validate().is_err())
                    || revision.is_none_or(|v| {
                        v.len() != 32
                            || !v
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                {
                    return self.finish(rejected("physical_snapshot_unavailable"));
                }
                match self.physical_plan(
                    snapshot.expect("validated snapshot"),
                    revision.expect("validated revision"),
                ) {
                    Ok(plan) => self.finish(PlanProgress::Complete(Box::new(
                        ProviderResponse::Planned { plan },
                    ))),
                    Err(reason) => self.finish(rejected(reason)),
                }
            }
        }
    }
    fn physical_plan(
        &self,
        mut configuration: physical_display::Configuration,
        topology_revision: &str,
    ) -> Result<ResourcePlan, &'static str> {
        let settings: DisplaySettings = serde_json::from_value(
            serde_json::to_value(&self.request.settings).map_err(|_| "invalid_settings")?,
        )
        .map_err(|_| "invalid_settings")?;
        if settings.scaling != ScalingSetting::Preserve
            || settings.layout != LayoutSetting::Preserve
            || settings.hdr != HdrSetting::Preserve
            || settings.hdr_request_override != HdrOverrideSetting::FollowClient
            || settings.retention != RetentionSetting::UntilSessionEnds
            || settings.keepalive_while_paused
            || settings.enforce_while_paused
        {
            return Err("unsupported_physical_policy");
        }
        // HDR preserve means no independent HDR state operation, even when
        // the discovery snapshot can read the current advanced-color bit.
        for display in &mut configuration.displays {
            display.hdr_enabled = None;
        }
        let selected_id = select_physical(&configuration, &settings)?.id.clone();
        let selected = configuration
            .displays
            .iter_mut()
            .find(|display| display.id == selected_id)
            .ok_or("physical_target_unavailable")?;
        match settings.resolution {
            ResolutionSetting::Preserve => {}
            ResolutionSetting::Manual => {
                selected.width = settings.width;
                selected.height = settings.height;
            }
            ResolutionSetting::Client => {
                let mode = self
                    .request
                    .requested_video
                    .as_ref()
                    .ok_or("missing_requested_video")?;
                selected.width = mode.width;
                selected.height = mode.height;
            }
        }
        match settings.refresh {
            RefreshSetting::Preserve => {}
            RefreshSetting::Manual => {
                selected.refresh = physical_display::Rational {
                    numerator: settings.refresh_numerator,
                    denominator: settings.refresh_denominator,
                }
            }
            RefreshSetting::Client => {
                let mode = self
                    .request
                    .requested_video
                    .as_ref()
                    .ok_or("missing_requested_video")?;
                selected.refresh = physical_display::Rational {
                    numerator: mode.refresh_millihz,
                    denominator: 1000,
                };
            }
            RefreshSetting::HighestAvailable => return Err("mode_enumeration_unavailable"),
        }
        configuration
            .validate()
            .map_err(|_| "unsupported_physical_configuration")?;
        let (domain_id, domain_revision) = self
            .physical_domain
            .as_ref()
            .ok_or("physical_domain_unavailable")?;
        let resources: Vec<_> = configuration
            .displays
            .iter()
            .map(|display| PlannedResource {
                provider: descriptor::PROVIDER.into(),
                resource_id: display.id.clone(),
                incarnation: None,
                expected_revision: None,
                execution_domain: self.request.consumer_requirements.execution_domain.clone(),
                mutation_domains: vec![domain_id.clone()],
                access: ResourceAccess::Exclusive,
            })
            .collect();
        let obligations: Vec<_> = configuration
            .displays
            .iter()
            .map(|display| ResourceObligation {
                obligation_id: format!(
                    "physical-cleanup-{}",
                    stable_hex("physical-obligation", &display.id)
                ),
                provider: descriptor::PROVIDER.into(),
                resource_id: display.id.clone(),
                mutation_domain: Some(domain_id.clone()),
                depends_on: vec![],
                cleanup_method: MethodRef {
                    service: descriptor::SERVICE.into(),
                    method: "lifecycle_callback".into(),
                    interface_major: 1,
                    interface_minor: 0,
                    schema_revision: 1,
                },
                payload: json!({"service":physical_display::SERVICE,"identity":display.id}),
            })
            .collect();
        let plan = ResourcePlan {
            plan_id: format!(
                "display-plan-{}",
                stable_hex("plan", &self.request.transition_id)
            ),
            revision: self.request.provider_sequence,
            resources,
            mutation_domains: vec![MutationDomainPlan {
                domain: domain_id.clone(),
                expected_revision: *domain_revision,
                borrowers: BTreeMap::new(),
                access: ResourceAccess::Exclusive,
            }],
            required_capabilities: vec![],
            constraints: json!({"physical":{"provider":physical_display::SERVICE,"configuration":configuration,"expected_topology_revision":topology_revision,"expected_mutation_domain_id":domain_id,"expected_mutation_domain_revision":domain_revision}}),
            obligations,
            affected_consumers: vec![],
            consumer_change: ConsumerChange::ReconnectRequired,
            candidate_constraint: None,
            allowed_degradation: vec![],
        };
        extension_api::validate_resource_plan(&plan).map_err(|_| "invalid_resource_plan")?;
        Ok(plan)
    }
    fn release_plan(&self, payload: &Value) -> Result<ResourcePlan, &'static str> {
        let (prior, domain, cleanup) = self
            .release
            .as_ref()
            .ok_or("release_ownership_unverified")?;
        let saved = prior.borrow.as_ref().ok_or("missing_release_borrow")?;
        let observed: virtual_display::ObservedOutput = serde_json::from_value(
            payload
                .get("observed_output")
                .cloned()
                .ok_or("release_borrow_unverified")?,
        )
        .map_err(|_| "release_borrow_unverified")?;
        let current: virtual_display::MutationDomain = serde_json::from_value(
            payload
                .get("mutation_domain")
                .cloned()
                .ok_or("release_borrow_unverified")?,
        )
        .map_err(|_| "release_borrow_unverified")?;
        if payload.get("ok").and_then(Value::as_bool) != Some(true)
            || payload.get("borrow_id").and_then(Value::as_str) != Some(saved.borrow_id.as_str())
            || observed != saved.observed_output
            || observed.width != prior.width
            || observed.height != prior.height
            || observed.refresh_millihz != prior.refresh_millihz
            || current.id != prior.domain_id
            || current.scope != "provider_session"
            || current.revision != domain.expected_revision
            || current.borrowers != domain.borrowers.len() as u64
            || current.pending_mutations != 0
        {
            return Err("release_borrow_unverified");
        }
        let revision = self.request.provider_sequence;
        let mut retained = prior.clone();
        retained.borrow = None;
        let resource = PlannedResource {
            provider: descriptor::PROVIDER.into(),
            resource_id: prior.identity.clone(),
            incarnation: None,
            expected_revision: None,
            execution_domain: self.request.consumer_requirements.execution_domain.clone(),
            mutation_domains: vec![prior.domain_id.clone()],
            access: ResourceAccess::Exclusive,
        };
        let plan = ResourcePlan {
            plan_id: format!(
                "display-plan-{}",
                stable_hex("plan", &self.request.transition_id)
            ),
            revision,
            resources: vec![resource],
            mutation_domains: vec![domain.clone()],
            required_capabilities: vec![],
            constraints: json!({"virtual_display":retained}),
            obligations: vec![cleanup.clone()],
            affected_consumers: vec![],
            consumer_change: ConsumerChange::ReconnectRequired,
            candidate_constraint: Some(BindingConstraint {
                capture_provider: CAPTURE.into(),
                selector_schema: SELECTOR.into(),
                resource_provider: descriptor::PROVIDER.into(),
                resource_id: prior.identity.clone(),
                incarnation: None,
                execution_domain: self.request.consumer_requirements.execution_domain.clone(),
                mode: Some(VideoMode {
                    width: prior.width,
                    height: prior.height,
                    refresh_millihz: prior.refresh_millihz,
                    hdr: prior.hdr_enabled,
                }),
                plan_revision: revision,
            }),
            allowed_degradation: vec![],
        };
        extension_api::validate_resource_plan(&plan).map_err(|_| "invalid_resource_plan")?;
        Ok(plan)
    }
    fn virtual_plan(&self, payload: &Value) -> Result<ResourcePlan, &'static str> {
        let Selection::Virtual {
            identity,
            reference_id,
            mode,
            layout,
        } = &self.selection
        else {
            return Err("invalid_selection");
        };
        if payload.get("ok").and_then(Value::as_bool) != Some(true)
            || payload.get("enabled").and_then(Value::as_bool) != Some(true)
            || payload.get("native_supported").and_then(Value::as_bool) != Some(true)
            || payload.get("recovery_ready").and_then(Value::as_bool) != Some(true)
            || payload.get("driver").and_then(Value::as_str) != Some("libvirtualdisplay")
            || payload.get("ownership_authority").and_then(Value::as_str) != Some("unix_uid_broker")
        {
            return Err("virtual_provider_unavailable");
        }
        if payload.get("reference_owned").and_then(Value::as_bool) != Some(false) {
            return Err("existing_virtual_reference_requires_reconciliation");
        }
        let monitors = payload
            .get("monitors")
            .and_then(Value::as_array)
            .ok_or("invalid_monitor_status")?;
        if let Some(session) = &self.session {
            let old = &session.obligation;
            if old.width != mode.width
                || old.height != mode.height
                || old.refresh_millihz != mode.refresh_millihz
                || old.hdr_enabled != mode.hdr
            {
                return Err("mode_change_requires_retirement");
            }
            let [monitor] = monitors.as_slice() else {
                return Err("session_monitor_unverified");
            };
            let spec = monitor
                .get("specification")
                .ok_or("session_monitor_unverified")?;
            let saved = old.borrow.as_ref().ok_or("session_borrow_unverified")?;
            if spec.get("identity").and_then(Value::as_str) != Some(identity)
                || spec.get("width").and_then(Value::as_u64) != Some(u64::from(old.width))
                || spec.get("height").and_then(Value::as_u64) != Some(u64::from(old.height))
                || spec.get("refresh_millihz").and_then(Value::as_u64)
                    != Some(u64::from(old.refresh_millihz))
                || spec.get("name").and_then(Value::as_str) != Some(old.name.as_str())
                || spec.get("hdr_enabled").and_then(Value::as_bool) != Some(old.hdr_enabled)
                || monitor.get("reference_owned").and_then(Value::as_bool) != Some(false)
                || monitor.get("state").and_then(Value::as_str) != Some("ready")
                || monitor
                    .get("virtual_display_layout")
                    .and_then(Value::as_str)
                    != Some(old.layout.as_str())
                || monitor
                    .get("dd_virtual_display_scale")
                    .and_then(Value::as_i64)
                    != old.scale.map(i64::from)
                || monitor.get("capture_output").and_then(Value::as_str)
                    != Some(format!("kwin:{}", saved.observed_output.output_name).as_str())
                || monitor.pointer("/ready/active").and_then(Value::as_bool) != Some(true)
            {
                return Err("session_monitor_unverified");
            }
        } else if !monitors.is_empty() {
            return Err("existing_virtual_reference_requires_reconciliation");
        }
        let domain = payload
            .get("mutation_domain")
            .and_then(Value::as_object)
            .ok_or("mutation_domain_unavailable")?;
        let id = domain
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| {
                s.starts_with("provider_session:")
                    && s.len() <= 128
                    && s.bytes().all(|b| b.is_ascii_graphic())
            })
            .ok_or("invalid_mutation_domain")?;
        let revision = domain
            .get("revision")
            .and_then(Value::as_u64)
            .ok_or("invalid_mutation_domain")?;
        let expected_borrowers = if self.session.is_some() { 1 } else { 0 };
        if domain.get("scope").and_then(Value::as_str) != Some("provider_session")
            || domain.get("borrowers").and_then(Value::as_u64) != Some(expected_borrowers)
            || domain.get("pending_mutations").and_then(Value::as_u64) != Some(0)
        {
            return Err("mutation_domain_busy");
        }
        let provider_settings = payload
            .get("settings")
            .and_then(Value::as_object)
            .ok_or("provider_settings_unavailable")?;
        if provider_settings
            .get("dd_virtual_display_scale")
            .and_then(Value::as_i64)
            != Some(0)
        {
            return Err("scale_unsupported");
        }
        let layout = match layout {
            Some(value) => value.as_str(),
            None => provider_settings
                .get("virtual_display_layout")
                .and_then(Value::as_str)
                .ok_or("layout_unavailable")?,
        };
        if !matches!(layout, "exclusive" | "extended") {
            return Err("layout_unsupported");
        }
        if let Some(session) = &self.session
            && (session.obligation.layout != layout
                || session.obligation.domain_id != id
                || session.observed_revision != Some(revision))
        {
            return Err("session_domain_changed");
        }
        let plan_revision = self.request.provider_sequence;
        let selection = VirtualObligation {
            provider_service: virtual_display::SERVICE.into(),
            identity: identity.clone(),
            reference_id: reference_id.clone(),
            width: mode.width,
            height: mode.height,
            refresh_millihz: mode.refresh_millihz,
            name: "Amaterasu".into(),
            hdr_enabled: false,
            scale: Some(0),
            layout: layout.into(),
            domain_id: id.into(),
            domain_revision: revision,
            geometry_revision: plan_revision,
            borrow: None,
            reference_released: false,
        };
        let resource = PlannedResource {
            provider: descriptor::PROVIDER.into(),
            resource_id: identity.clone(),
            incarnation: None,
            expected_revision: None,
            execution_domain: self.request.consumer_requirements.execution_domain.clone(),
            mutation_domains: vec![id.into()],
            access: ResourceAccess::Exclusive,
        };
        let constraint = BindingConstraint {
            capture_provider: CAPTURE.into(),
            selector_schema: SELECTOR.into(),
            resource_provider: descriptor::PROVIDER.into(),
            resource_id: identity.clone(),
            incarnation: None,
            execution_domain: self.request.consumer_requirements.execution_domain.clone(),
            mode: Some(mode.clone()),
            plan_revision,
        };
        let cleanup = ResourceObligation {
            obligation_id: format!("virtual-cleanup-{}", stable_hex("obligation", reference_id)),
            provider: descriptor::PROVIDER.into(),
            resource_id: identity.clone(),
            mutation_domain: Some(id.into()),
            depends_on: vec![],
            cleanup_method: MethodRef {
                service: descriptor::SERVICE.into(),
                method: "lifecycle_callback".into(),
                interface_major: 1,
                interface_minor: 0,
                schema_revision: 1,
            },
            payload: json!({"service":virtual_display::SERVICE,"identity":identity,"reference_id":reference_id}),
        };
        let borrowers = if let Some(session) = &self.session {
            match &session.target {
                LifecycleTarget::Session {
                    session_id,
                    generation,
                    ..
                } => BTreeMap::from([(session_id.clone(), *generation)]),
                _ => return Err("invalid_session_target"),
            }
        } else {
            BTreeMap::new()
        };
        let plan = ResourcePlan {
            plan_id: format!(
                "display-plan-{}",
                stable_hex("plan", &self.request.transition_id)
            ),
            revision: plan_revision,
            resources: vec![resource],
            mutation_domains: vec![MutationDomainPlan {
                domain: id.into(),
                expected_revision: revision,
                borrowers,
                access: ResourceAccess::Exclusive,
            }],
            required_capabilities: vec![],
            constraints: json!({"virtual_display":selection}),
            obligations: vec![cleanup],
            affected_consumers: vec![],
            consumer_change: ConsumerChange::ReconnectRequired,
            candidate_constraint: Some(constraint),
            allowed_degradation: vec![],
        };
        extension_api::validate_resource_plan(&plan).map_err(|_| "invalid_resource_plan")?;
        Ok(plan)
    }
    fn finish(&mut self, result: PlanProgress) -> PlanProgress {
        self.finished = Some(result.clone());
        result
    }
}
fn target_ids(target: &LifecycleTarget) -> Result<(&str, String), &'static str> {
    match target {
        LifecycleTarget::Session { session_id, .. } => Ok((
            session_id,
            serde_json::to_string(&("session", session_id)).map_err(|_| "invalid_target")?,
        )),
        LifecycleTarget::Stream {
            session_id,
            stream_id,
            ..
        } => Ok((
            session_id,
            serde_json::to_string(&("stream", session_id, stream_id))
                .map_err(|_| "invalid_target")?,
        )),
        _ => Err("unsupported_target"),
    }
}
fn stable_hex(namespace: &str, value: &str) -> String {
    let input =
        serde_json::to_vec(&(descriptor::PROVIDER, namespace, value)).expect("strings serialize");
    format!("{:x}", Sha256::digest(input))[..32].into()
}
fn stable_uuid(namespace: &str, value: &str) -> String {
    let mut bytes = Sha256::digest(
        serde_json::to_vec(&(descriptor::PROVIDER, namespace, value)).expect("strings serialize"),
    );
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
fn resolve_mode(
    request: &ProviderRequest,
    settings: &DisplaySettings,
) -> Result<VideoMode, &'static str> {
    let mut mode = request
        .requested_video
        .clone()
        .ok_or("missing_requested_video")?;
    if mode.hdr {
        return Err("hdr_unsupported");
    }
    if settings.resolution == ResolutionSetting::Manual {
        mode.width = settings.width;
        mode.height = settings.height;
    }
    match settings.refresh {
        RefreshSetting::Manual => {
            let n = u64::from(settings.refresh_numerator) * 1000;
            let d = u64::from(settings.refresh_denominator);
            if d == 0 || n % d != 0 {
                return Err("refresh_unrepresentable");
            }
            mode.refresh_millihz = u32::try_from(n / d).map_err(|_| "refresh_unrepresentable")?;
        }
        RefreshSetting::HighestAvailable => return Err("mode_enumeration_unavailable"),
        _ => {}
    }
    if !(320..=7680).contains(&mode.width)
        || !(200..=4320).contains(&mode.height)
        || !(1000..=1_000_000).contains(&mode.refresh_millihz)
    {
        return Err("invalid_mode");
    }
    Ok(mode)
}
fn select_physical<'a>(
    configuration: &'a physical_display::Configuration,
    settings: &DisplaySettings,
) -> Result<&'a physical_display::DisplaySetting, &'static str> {
    let mut candidates =
        configuration
            .displays
            .iter()
            .filter(|display| match settings.physical_target {
                PhysicalTargetSetting::Automatic => display.x == 0 && display.y == 0,
                PhysicalTargetSetting::Identifier => display.id == settings.physical_display_id,
            });
    let selected = candidates.next().ok_or("physical_target_unavailable")?;
    if candidates.next().is_some() {
        return Err("physical_target_ambiguous");
    }
    Ok(selected)
}
fn make_exchange(
    service: &str,
    payload: Value,
    request: &ProviderRequest,
    label: &str,
    parent: Option<u64>,
    timeout_ms: u64,
) -> Result<Exchange, &'static str> {
    if timeout_ms == 0 {
        return Err("deadline_expired");
    }
    let operation_id = format!(
        "display-plan.{}.{}",
        stable_hex("broker", &request.operation_id),
        label
    );
    Ok(Exchange {
        command: Command::Request {
            service: service.into(),
            payload,
            timeout_ms,
            operation_id,
            parent,
        },
        id: None,
        result: None,
        uncertain: false,
    })
}
fn rejected(reason: &str) -> PlanProgress {
    PlanProgress::Complete(Box::new(ProviderResponse::Rejected {
        reason: reason.into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    fn request() -> ProviderRequest {
        let mut settings =
            amaterasu_configuration_schema::defaults(&crate::settings_schema::definitions())
                .unwrap();
        settings.insert("enabled".into(), json!(true));
        serde_json::from_value(json!({"provider_sequence":3,"operation":"resource_plan","version":1,"transition_id":"transition-1","operation_id":"op-1","target":{"kind":"stream","host_epoch":"epoch-1","session_id":"session-1","stream_id":"stream-1","generation":1},"phase":"stream.prepare","settings_revision":"settings-1","settings":settings,"intent":"initial","reason":null,"requested_video":{"width":1920,"height":1080,"refresh_millihz":60000,"hdr":false},"consumer_requirements":{"execution_domain":"desktop","capture_providers":[CAPTURE],"selector_schemas":[SELECTOR]},"remaining_ms":5000,"plan_revision":null,"admission_id":null,"approved_plan":null})).unwrap()
    }
    fn status() -> Value {
        json!({"ok":true,"enabled":true,"native_supported":true,"driver":"libvirtualdisplay","ownership_authority":"unix_uid_broker","recovery_ready":true,"reference_owned":false,"monitors":[],"mutation_domain":{"id":"provider_session:abc","revision":7,"borrowers":0,"pending_mutations":0,"scope":"provider_session"},"settings":{"virtual_display_layout":"extended","dd_virtual_display_scale":0}})
    }
    fn run(status: Value) -> (PlanProgress, Vec<Command>) {
        let mut planner = Planner::new(COORDINATOR, request(), Some(2), 0, |_| true).unwrap();
        let mut responses = VecDeque::from([
            Ok(Response::Accepted { id: 4 }),
            Ok(Response::Result { payload: status }),
            Ok(Response::Ok),
        ]);
        let mut commands = Vec::new();
        let mut result = PlanProgress::Waiting;
        for tick in 0..3 {
            result = planner.poll(tick, &mut |cmd| {
                commands.push(cmd);
                responses.pop_front().unwrap()
            });
        }
        (result, commands)
    }
    #[test]
    fn available_provider_builds_bounded_plan_without_mutation() {
        let (result, commands) = run(status());
        let PlanProgress::Complete(response) = result else {
            panic!("not planned: {result:?}")
        };
        let ProviderResponse::Planned { plan } = *response else {
            panic!("unexpected response")
        };
        assert_eq!(plan.resources[0].provider, descriptor::PROVIDER);
        assert_eq!(plan.mutation_domains[0].expected_revision, 7);
        assert!(plan.mutation_domains[0].borrowers.is_empty());
        assert_eq!(
            plan.constraints["virtual_display"]["domain_id"],
            "provider_session:abc"
        );
        assert_eq!(
            plan.obligations[0].payload["service"],
            virtual_display::SERVICE
        );
        assert_eq!(plan.candidate_constraint.as_ref().unwrap().plan_revision, 3);
        assert_eq!(extension_api::validate_resource_plan(&plan), Ok(()));
        assert_eq!(
            extension_api::validate_provider_response(
                &request(),
                &ProviderResponse::Planned { plan: plan.clone() }
            ),
            Ok(())
        );
        assert!(
            matches!(&commands[..],[Command::Request {service,payload,..},Command::TakeResult {..},Command::ReleaseResult {..}] if service==virtual_display::SERVICE && payload["action"]=="status")
        );
    }
    #[test]
    fn releases_reuse_owned_geometry_and_validate_live_borrow() {
        for session_scope in [false, true] {
            let mut req = request();
            req.requested_video = None;
            if session_scope {
                req.target = serde_json::from_value(json!({"kind":"session","host_epoch":"epoch-1","session_id":"session-1","generation":1})).unwrap();
                req.phase = extension_api::LifecyclePhase::SessionRelease;
            } else {
                req.phase = extension_api::LifecyclePhase::StreamRelease;
            }
            let (session, reference) = target_ids(&req.target).unwrap();
            let identity = stable_uuid("display", session);
            let reference = format!("ref-{}", stable_hex("reference", &reference));
            let observation = json!({"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1920,"height":1080,"refresh_millihz":60000});
            let domain = json!({"id":"provider_session:abc","revision":7,"borrowers":1,"pending_mutations":0,"scope":"provider_session"});
            let borrow = json!({"borrow_id":"a".repeat(64),"observed_output":observation,"mutation_domain":domain});
            let prior: VirtualObligation = serde_json::from_value(json!({"provider_service":virtual_display::SERVICE,"identity":identity,"reference_id":reference,"width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false,"scale":0,"layout":"extended","domain_id":"provider_session:abc","domain_revision":6,"geometry_revision":1,"borrow":borrow,"reference_released":false})).unwrap();
            let domain = MutationDomainPlan {
                domain: "provider_session:abc".into(),
                expected_revision: 7,
                borrowers: BTreeMap::from([("owner".into(), 1)]),
                access: ResourceAccess::Exclusive,
            };
            let cleanup = ResourceObligation {
                obligation_id: "cleanup-1".into(),
                provider: descriptor::PROVIDER.into(),
                resource_id: prior.identity.clone(),
                mutation_domain: Some(prior.domain_id.clone()),
                depends_on: vec![],
                cleanup_method: MethodRef {
                    service: descriptor::SERVICE.into(),
                    method: "lifecycle_callback".into(),
                    interface_major: 1,
                    interface_minor: 0,
                    schema_revision: 1,
                },
                payload: json!({"service":virtual_display::SERVICE,"identity":prior.identity,"reference_id":prior.reference_id}),
            };
            let mut planner = Planner::new_release(
                COORDINATOR,
                req.clone(),
                prior.clone(),
                ReleaseAuthority { domain, cleanup },
                Some(2),
                0,
                |_| true,
            )
            .unwrap();
            let mut live = borrow.clone();
            live["ok"] = json!(true);
            let plan = planner.release_plan(&live).unwrap();
            assert_eq!(plan.constraints["virtual_display"]["domain_revision"], 6);
            assert_eq!(plan.constraints["virtual_display"]["geometry_revision"], 1);
            assert_eq!(plan.mutation_domains[0].expected_revision, 7);
            assert_eq!(
                extension_api::validate_provider_response(
                    &req,
                    &ProviderResponse::Planned { plan }
                ),
                Ok(())
            );
            let mut replies = VecDeque::from([
                Ok(Response::Accepted { id: 5 }),
                Ok(Response::Result {
                    payload: live.clone(),
                }),
                Ok(Response::Ok),
            ]);
            let mut commands = Vec::new();
            let mut progress = PlanProgress::Waiting;
            for tick in 0..3 {
                progress = planner.poll(tick, &mut |command| {
                    commands.push(command);
                    replies.pop_front().unwrap()
                });
            }
            assert!(
                matches!(progress, PlanProgress::Complete(response) if matches!(*response, ProviderResponse::Planned { .. }))
            );
            assert!(
                matches!(&commands[0], Command::Request { payload, .. } if payload["action"] == "validate_borrow")
            );
            live["observed_output"]["registry_global"] = json!(8);
            assert_eq!(
                planner.release_plan(&live).unwrap_err(),
                "release_borrow_unverified"
            );
        }
    }
    #[test]
    fn stream_reuses_only_verified_session_reference_and_matching_live_output() {
        let mut planner = Planner::new(COORDINATOR, request(), Some(2), 0, |_| true).unwrap();
        let Selection::Virtual { identity, .. } = &planner.selection else {
            panic!()
        };
        let identity = identity.clone();
        let target:LifecycleTarget=serde_json::from_value(json!({"kind":"session","host_epoch":"epoch-1","session_id":"session-1","generation":1})).unwrap();
        let session_ref = format!(
            "ref-{}",
            stable_hex("reference", &target_ids(&target).unwrap().1)
        );
        let observation = json!({"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1920,"height":1080,"refresh_millihz":60000});
        let domain = json!({"id":"provider_session:abc","revision":7,"borrowers":1,"pending_mutations":0,"scope":"provider_session"});
        let borrow = json!({"borrow_id":"a".repeat(64),"observed_output":observation,"mutation_domain":domain});
        let obligation:VirtualObligation=serde_json::from_value(json!({"provider_service":virtual_display::SERVICE,"identity":identity,"reference_id":session_ref,"width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false,"scale":0,"layout":"extended","domain_id":"provider_session:abc","domain_revision":6,"geometry_revision":1,"borrow":borrow,"reference_released":false})).unwrap();
        let session =
            VerifiedSessionDisplay::authenticate(target, obligation, |_, _| true).unwrap();
        planner.attach_session(session, 0).unwrap();
        let mut provider_status = status();
        provider_status["mutation_domain"] = domain.clone();
        provider_status["monitors"] = json!([{"reference_owned":false,"specification":{"identity":identity,"width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false},"state":"ready","virtual_display_layout":"extended","dd_virtual_display_scale":0,"capture_output":"kwin:Virtual-1","ready":{"active":true}}]);
        let mut live = borrow.clone();
        live["ok"] = json!(true);
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 1 }),
            Ok(Response::Result { payload: live }),
            Ok(Response::Ok),
            Ok(Response::Accepted { id: 2 }),
            Ok(Response::Result {
                payload: provider_status.clone(),
            }),
            Ok(Response::Ok),
        ]);
        let mut result = PlanProgress::Waiting;
        for tick in 0..6 {
            result = planner.poll(tick, &mut |_| replies.pop_front().unwrap());
        }
        let PlanProgress::Complete(response) = result else {
            panic!("{result:?}")
        };
        let ProviderResponse::Planned { plan } = *response else {
            panic!("expected plan")
        };
        assert_eq!(
            plan.mutation_domains[0].borrowers.get("session-1"),
            Some(&1)
        );
        assert_eq!(plan.mutation_domains[0].expected_revision, 7);
        assert_ne!(
            plan.constraints["virtual_display"]["reference_id"],
            json!(session_ref)
        );
        let mut foreign = provider_status.clone();
        foreign["monitors"][0]["specification"]["identity"] = json!("other");
        assert_eq!(
            planner.virtual_plan(&foreign).unwrap_err(),
            "session_monitor_unverified"
        );
        let mut busy = provider_status.clone();
        busy["mutation_domain"]["borrowers"] = json!(2);
        assert_eq!(
            planner.virtual_plan(&busy).unwrap_err(),
            "mutation_domain_busy"
        );
        let mut drift = provider_status;
        drift["mutation_domain"]["revision"] = json!(8);
        assert_eq!(
            planner.virtual_plan(&drift).unwrap_err(),
            "session_domain_changed"
        );
    }
    #[test]
    fn busy_or_incomplete_domain_never_produces_a_plan() {
        let mut busy = status();
        busy["mutation_domain"]["borrowers"] = json!(1);
        assert!(
            matches!(run(busy).0,PlanProgress::Complete(response) if matches!(&*response,ProviderResponse::Rejected { reason } if reason=="mutation_domain_busy"))
        );
        let mut missing = status();
        missing.as_object_mut().unwrap().remove("mutation_domain");
        assert!(
            matches!(run(missing).0,PlanProgress::Complete(response) if matches!(&*response,ProviderResponse::Rejected { reason } if reason=="mutation_domain_unavailable"))
        );
    }
    #[test]
    fn authority_and_unsupported_requested_mode_fail_closed() {
        assert!(Planner::new("other", request(), None, 0, |_| true).is_err());
        assert!(Planner::new(COORDINATOR, request(), None, 0, |_| false).is_err());
        let mut hdr = request();
        hdr.requested_video.as_mut().unwrap().hdr = true;
        assert!(Planner::new(COORDINATOR, hdr, None, 0, |_| true).is_err());
        assert_ne!(
            stable_hex(
                "reference",
                &serde_json::to_string(&("stream", "a:b", "c")).unwrap()
            ),
            stable_hex(
                "reference",
                &serde_json::to_string(&("stream", "a", "b:c")).unwrap()
            )
        );
    }
    #[test]
    fn ambiguous_admission_or_provider_reply_never_produces_a_plan() {
        let mut planner = Planner::new(COORDINATOR, request(), None, 0, |_| true).unwrap();
        for tick in 0..3 {
            assert_eq!(
                planner.poll(tick, &mut |_| Err("lost".into())),
                PlanProgress::Waiting
            );
        }
        assert_eq!(
            planner.poll(3, &mut |_| panic!("bounded")),
            PlanProgress::Unknown
        );
        let mut invalid = status();
        invalid["native_supported"] = json!(false);
        assert!(matches!(
            run(invalid).0,
            PlanProgress::Complete(response) if matches!(*response, ProviderResponse::Rejected { .. })
        ));
    }
    #[test]
    fn physical_selection_never_falls_back_or_guesses_among_clones() {
        let display = |id: &str, x| physical_display::DisplaySetting {
            id: id.into(),
            width: 1920,
            height: 1080,
            refresh: physical_display::Rational {
                numerator: 60,
                denominator: 1,
            },
            x,
            y: 0,
            rotation: physical_display::Rotation::Identity,
            hdr_enabled: None,
        };
        let mut settings = DisplaySettings::default();
        let mut configuration = physical_display::Configuration {
            displays: vec![display("primary", 0), display("other", 1920)],
        };
        assert_eq!(
            select_physical(&configuration, &settings).unwrap().id,
            "primary"
        );
        settings.physical_target = PhysicalTargetSetting::Identifier;
        settings.physical_display_id = "other".into();
        assert_eq!(
            select_physical(&configuration, &settings).unwrap().id,
            "other"
        );
        settings.physical_display_id = "missing".into();
        assert_eq!(
            select_physical(&configuration, &settings),
            Err("physical_target_unavailable")
        );
        settings.physical_target = PhysicalTargetSetting::Automatic;
        configuration.displays[1].x = 0;
        assert_eq!(
            select_physical(&configuration, &settings),
            Err("physical_target_ambiguous")
        );
    }
    #[test]
    fn physical_plan_fences_the_whole_snapshot_with_separate_revisions() {
        let mut planner = Planner::new(COORDINATOR, request(), Some(2), 0, |_| true).unwrap();
        planner.physical_domain = Some(("physical_provider_session:abc".into(), 9));
        let display = |id: &str, x| physical_display::DisplaySetting {
            id: id.into(),
            width: 1920,
            height: 1080,
            refresh: physical_display::Rational {
                numerator: 60,
                denominator: 1,
            },
            x,
            y: 0,
            rotation: physical_display::Rotation::Identity,
            hdr_enabled: Some(true),
        };
        let snapshot = physical_display::Configuration {
            displays: vec![display("primary", 0), display("other", 1920)],
        };
        let topology = "0123456789abcdef0123456789abcdef";
        let plan = planner.physical_plan(snapshot, topology).unwrap();
        assert_eq!(plan.resources.len(), 2);
        assert_eq!(plan.obligations.len(), 2);
        assert_eq!(plan.mutation_domains[0].expected_revision, 9);
        assert_eq!(
            plan.constraints["physical"]["expected_topology_revision"],
            topology
        );
        assert_eq!(
            plan.constraints["physical"]["expected_mutation_domain_revision"],
            9
        );
        assert_eq!(
            plan.constraints["physical"]["expected_mutation_domain_id"],
            "physical_provider_session:abc"
        );
        assert!(plan.candidate_constraint.is_none());
        assert_eq!(extension_api::validate_resource_plan(&plan), Ok(()));
        assert!(
            plan.constraints["physical"]["configuration"]["displays"]
                .as_array()
                .unwrap()
                .iter()
                .all(|d| d["hdr_enabled"].is_null())
        );
        planner.physical_domain = None;
        let configuration =
            serde_json::from_value(plan.constraints["physical"]["configuration"].clone()).unwrap();
        assert_eq!(
            planner.physical_plan(configuration, topology),
            Err("physical_domain_unavailable")
        );
    }
}
