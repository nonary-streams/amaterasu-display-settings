//! Plans display settings against a coordinator-selected resource observation.
use crate::descriptor;
use crate::settings::{
    DisplaySettings, DisplayTargetSetting, HdrOverrideSetting, HdrSetting, LayoutSetting,
    PhysicalTargetSetting, RefreshSetting, ResolutionSetting, ScalingSetting,
};
use amaterasu_module_sdk::extension_api::{
    self, ConsumerChange, MethodRef, MutationDomainPlan, PlannedResource, ProviderOperation,
    ProviderRequest, ResourceAccess, ResourceObligation, ResourcePlan,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DISPLAY_TARGET_SCHEMA: &str = "amaterasu.display-target/1";
const DISPLAY_TARGET_DIGEST: &str =
    "ededc620113268bcae3990d492deeef039c5e9c5ff28067a676dd992fe6324ce";
const DISPLAY_CONTROL_SCHEMA: &str = "amaterasu.display-control/1";
const DISPLAY_CONTROL_DIGEST: &str =
    "c2c3ce866277cb29bbd9fbd947899917538d46b1020df3197fbd264159607d87";

/// Plan only from the coordinator-selected, frozen owner observation. The
/// coordinator authenticates the caller and target, validates the selected
/// schemas and installed control method, and rechecks the domain before effects.
pub fn plan_composed(request: &ProviderRequest) -> Result<ResourcePlan, &'static str> {
    use extension_api::{LifecyclePhase, LifecycleTarget, ResourceControlProposal, SchemaRef};
    if request.version != 2
        || request.operation != ProviderOperation::ResourcePlan
        || extension_api::validate_provider_request(request).is_err()
    {
        return Err("invalid_request");
    }
    if !matches!(
        (&request.phase, &request.target),
        (
            LifecyclePhase::SessionPrepare | LifecyclePhase::SessionRelease,
            LifecycleTarget::Session { .. }
        ) | (
            LifecyclePhase::StreamPrepare | LifecyclePhase::StreamRelease,
            LifecycleTarget::Stream { .. }
        )
    ) {
        return Err("invalid_phase_target");
    }
    let settings: DisplaySettings = serde_json::from_value(
        serde_json::to_value(&request.settings).map_err(|_| "invalid_settings")?,
    )
    .map_err(|_| "invalid_settings")?;
    if crate::settings_schema::validate(&request.settings).is_err()
        || settings.to_policy().is_err()
        || !settings.enabled
    {
        return Err("disabled_or_invalid_settings");
    }
    if matches!(
        request.phase,
        LifecyclePhase::SessionPrepare | LifecyclePhase::SessionRelease
    ) {
        return Ok(ResourcePlan {
            plan_id: format!(
                "display-plan-{}",
                stable_hex("plan", &request.transition_id)
            ),
            revision: request.provider_sequence,
            resources: vec![],
            mutation_domains: vec![],
            required_capabilities: vec![],
            constraints: json!({}),
            obligations: vec![],
            affected_consumers: vec![],
            consumer_change: ConsumerChange::Live,
            candidate_constraint: None,
            allowed_degradation: vec![],
            control_proposals: vec![],
            resource_disposition: None,
        });
    }
    let mut inputs = request.dependency_inputs.iter().filter(|input| {
        input.capability == "amaterasu.display-target"
            && input.schema.id == DISPLAY_TARGET_SCHEMA
            && input.schema.major == 1
            && input.schema.minor == 0
            && input.schema.digest == DISPLAY_TARGET_DIGEST
    });
    let output = inputs.next().ok_or("display_target_unavailable")?;
    if inputs.next().is_some()
        || output.producer != output.resource.provider
        || output.resource.execution_domain != request.consumer_requirements.execution_domain
    {
        return Err("ambiguous_or_invalid_display_target");
    }
    let data = &output.data;
    match settings.display_target {
        DisplayTargetSetting::Virtual
            if data["kind"] == "virtual" && data["physical_identity"].is_null() => {}
        DisplayTargetSetting::Physical if data["kind"] == "physical" => {
            let identity = data["physical_identity"]
                .as_str()
                .filter(|id| !id.is_empty())
                .ok_or("physical_target_unavailable")?;
            match settings.physical_target {
                PhysicalTargetSetting::Automatic if data["primary"] == true => {}
                PhysicalTargetSetting::Identifier if identity == settings.physical_display_id => {}
                _ => return Err("physical_target_unavailable"),
            }
        }
        _ => return Err("display_target_kind_unverified"),
    }
    if data["native_state"] != "active"
        || data["desired_activation"] != "active"
        || !matches!(
            data["retention_state"].as_str(),
            Some("active" | "retained")
        )
    {
        return Err("display_target_not_ready");
    }
    let observation = match output.domain_observations.as_slice() {
        [observation] => observation,
        _ => return Err("invalid_domain"),
    };
    let domain = observation.domain.as_str();
    let revision = observation.revision;
    let borrowers = observation.borrowers.clone();
    if borrowers.values().any(|count| *count == 0)
        || !observation.complete
        || revision == 0
        || output.resource.mutation_domain.as_deref() != Some(domain)
        || output
            .resource
            .mutation_domains
            .iter()
            .any(|id| id != domain)
    {
        return Err("invalid_domain");
    }
    let prepare = matches!(request.phase, LifecyclePhase::StreamPrepare);
    let arguments = if prepare {
        match data["control_state"].as_str() {
            Some("unconfigured") if data["snapshot_id"].is_null() => {}
            // The coordinator authenticates this exact handoff and its previous
            // release before dispatching the request to the planner.
            Some("restored")
                if data["snapshot_id"]
                    .as_str()
                    .is_some_and(|snapshot| !snapshot.is_empty() && snapshot.len() <= 128)
                    && crate::composition_callback::valid_preservation_proof(data) => {}
            _ => return Err("display_target_already_configured"),
        }
        composed_configure(request, &settings, data)?
    } else {
        let snapshot = data["snapshot_id"]
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or("missing_restore_snapshot")?;
        if data["control_state"] != "configured" {
            return Err("display_restore_unavailable");
        }
        json!({"operation":"restore","snapshot_id":snapshot})
    };
    let domains = vec![domain.to_owned()];
    let proposal_id = format!(
        "display-control-{}",
        stable_hex("proposal", &request.operation_id)
    );
    let method = MethodRef {
        service: output.producer_service.clone(),
        method: "resource_control".into(),
        interface_major: 2,
        interface_minor: 0,
        schema_revision: 1,
    };
    let proposal = ResourceControlProposal {
        proposal_id: proposal_id.clone(),
        output_id: output.output_id.clone(),
        owner_provider: output.producer.clone(),
        owner_service: output.producer_service.clone(),
        target: request.target.clone(),
        resource: output.resource.clone(),
        method,
        argument_schema: SchemaRef {
            id: DISPLAY_CONTROL_SCHEMA.into(),
            major: 1,
            minor: 0,
            digest: DISPLAY_CONTROL_DIGEST.into(),
        },
        arguments,
        access: ResourceAccess::Exclusive,
        mutation_domains: domains.clone(),
    };
    let obligation = ResourceObligation {
        obligation_id: format!(
            "display-cleanup-{}",
            stable_hex("cleanup", &output.output_id)
        ),
        provider: descriptor::PROVIDER.into(),
        resource_id: output.resource.resource_id.clone(),
        mutation_domain: Some(domain.into()),
        depends_on: vec![],
        cleanup_method: MethodRef {
            service: descriptor::SERVICE.into(),
            method: "lifecycle_callback".into(),
            interface_major: 2,
            interface_minor: 0,
            schema_revision: 1,
        },
        payload: json!({"output_id":output.output_id}),
    };
    let plan = ResourcePlan {
        plan_id: format!(
            "display-plan-{}",
            stable_hex("plan", &request.transition_id)
        ),
        revision: request.provider_sequence,
        resources: vec![PlannedResource {
            provider: output.resource.provider.clone(),
            resource_id: output.resource.resource_id.clone(),
            incarnation: Some(output.resource.incarnation.clone()),
            expected_revision: Some(output.resource.revision),
            execution_domain: output.resource.execution_domain.clone(),
            mutation_domains: domains,
            access: ResourceAccess::Exclusive,
        }],
        mutation_domains: vec![MutationDomainPlan {
            domain: domain.into(),
            expected_revision: revision,
            borrowers,
            access: ResourceAccess::Exclusive,
        }],
        required_capabilities: vec![],
        constraints: json!({"display_control":{"output_id":output.output_id}}),
        obligations: vec![obligation],
        affected_consumers: vec![],
        consumer_change: ConsumerChange::ReconnectRequired,
        candidate_constraint: None,
        allowed_degradation: vec![],
        control_proposals: vec![proposal],
        resource_disposition: None,
    };
    extension_api::validate_resource_plan(&plan).map_err(|_| "invalid_resource_plan")?;
    Ok(plan)
}

fn composed_configure(
    request: &ProviderRequest,
    settings: &DisplaySettings,
    data: &Value,
) -> Result<Value, &'static str> {
    if settings.scaling != ScalingSetting::Preserve
        || settings.hdr != HdrSetting::Preserve
        || settings.hdr_request_override != HdrOverrideSetting::FollowClient
        || data["mode"]["hdr"] == true
        || (settings.display_target == DisplayTargetSetting::Physical
            && settings.layout != LayoutSetting::Preserve)
    {
        return Err("display_policy_unsupported");
    }
    let observed = &data["mode"];
    let client = request.requested_video.as_ref();
    let width = match settings.resolution {
        ResolutionSetting::Preserve => observed["width"].as_u64(),
        ResolutionSetting::Client => client.map(|mode| u64::from(mode.width)),
        ResolutionSetting::Manual => Some(u64::from(settings.width)),
    }
    .ok_or("missing_resolution")?;
    let height = match settings.resolution {
        ResolutionSetting::Preserve => observed["height"].as_u64(),
        ResolutionSetting::Client => client.map(|mode| u64::from(mode.height)),
        ResolutionSetting::Manual => Some(u64::from(settings.height)),
    }
    .ok_or("missing_resolution")?;
    let refresh = match settings.refresh {
        RefreshSetting::Preserve => observed["refresh_millihz"].as_u64(),
        RefreshSetting::Client => client.map(|mode| u64::from(mode.refresh_millihz)),
        RefreshSetting::Manual => {
            let n = u64::from(settings.refresh_numerator) * 1000;
            let d = u64::from(settings.refresh_denominator);
            if d == 0 || n % d != 0 {
                return Err("refresh_unrepresentable");
            }
            Some(n / d)
        }
        RefreshSetting::HighestAvailable => return Err("mode_enumeration_unavailable"),
    }
    .ok_or("missing_refresh")?;
    if !(320..=7680).contains(&width)
        || !(200..=4320).contains(&height)
        || !(1000..=1_000_000).contains(&refresh)
        || client.is_some_and(|mode| mode.hdr)
    {
        return Err("invalid_or_unsupported_mode");
    }
    let layout = match settings.layout {
        LayoutSetting::Preserve => "preserve",
        LayoutSetting::Exclusive => "exclusive",
        LayoutSetting::Extended => "extended",
        _ => return Err("layout_unsupported"),
    };
    Ok(
        json!({"operation":"configure","width":width,"height":height,"refresh_millihz":refresh,"hdr":"preserve","scaling":{"mode":"preserve"},"layout":layout}),
    )
}

fn stable_hex(namespace: &str, value: &str) -> String {
    let input =
        serde_json::to_vec(&(descriptor::PROVIDER, namespace, value)).expect("strings serialize");
    format!("{:x}", Sha256::digest(input))[..32].into()
}

#[cfg(test)]
mod tests {
    use super::*;
    const CAPTURE: &str = "amaterasu.capture-pipewire/1";
    const SELECTOR: &str = "amaterasu.kwin-wl-output/1";
    fn request() -> ProviderRequest {
        let mut settings =
            amaterasu_configuration_schema::defaults(&crate::settings_schema::definitions())
                .unwrap();
        settings.insert("enabled".into(), json!(true));
        serde_json::from_value(json!({"provider_sequence":3,"operation":"resource_plan","version":1,"transition_id":"transition-1","operation_id":"op-1","target":{"kind":"stream","host_epoch":"epoch-1","session_id":"session-1","stream_id":"stream-1","generation":1},"phase":"stream.prepare","settings_revision":"settings-1","settings":settings,"intent":"initial","reason":null,"requested_video":{"width":1920,"height":1080,"refresh_millihz":60000,"hdr":false},"consumer_requirements":{"execution_domain":"desktop","capture_providers":[CAPTURE],"selector_schemas":[SELECTOR]},"remaining_ms":5000,"plan_revision":null,"admission_id":null,"approved_plan":null})).unwrap()
    }
    fn composed_request() -> ProviderRequest {
        let mut value = serde_json::to_value(request()).unwrap();
        value["version"] = json!(2);
        value["dependency_inputs"] = json!([{
            "output_id":"output-1", "capability":"amaterasu.display-target",
            "schema":{"id":DISPLAY_TARGET_SCHEMA,"major":1,"minor":0,"digest":DISPLAY_TARGET_DIGEST},
            "producer":"example.owner", "producer_service":"example.owner/2",
            "origin":value["target"],
            "domain_observations":[{"domain":"domain-1","revision":4,"borrowers":{},"complete":true}],
            "resource":{"provider":"example.owner","resource_id":"output-1","incarnation":"inc-1","revision":3,"execution_domain":"desktop","mutation_domain":"domain-1","mutation_domains":["domain-1"]},
            "data":{"kind":"virtual","physical_identity":null,"primary":null,"desired_activation":"active","native_state":"active","retention_state":"active","control_state":"unconfigured","snapshot_id":null,
                "mode":{"width":1600,"height":900,"refresh_millihz":60000,"hdr":false},
                "capture_selector":{"provider":CAPTURE,"schema":SELECTOR,"selector":{}},"scale_percent":100,"layout":"extended"}
        }]);
        serde_json::from_value(value).unwrap()
    }
    #[test]
    fn composed_plan_uses_owner_observation_and_fences_unknown_restore() {
        let mut request = composed_request();
        let plan = plan_composed(&request).unwrap();
        let proposal = &plan.control_proposals[0];
        assert_eq!(proposal.owner_provider, "example.owner");
        assert_eq!(proposal.arguments["width"], 1600);
        assert_eq!(proposal.arguments["height"], 900);
        assert_eq!(plan.mutation_domains[0].expected_revision, 4);
        assert_eq!(proposal.method.interface_major, 2);
        request.phase = extension_api::LifecyclePhase::StreamRelease;
        assert_eq!(plan_composed(&request), Err("missing_restore_snapshot"));
        request.dependency_inputs[0].data["control_state"] = json!("configured");
        request.dependency_inputs[0].data["snapshot_id"] = json!("snapshot-1");
        let plan = plan_composed(&request).unwrap();
        assert_eq!(
            plan.control_proposals[0].arguments,
            json!({"operation":"restore","snapshot_id":"snapshot-1"})
        );
    }
    #[test]
    fn restored_handoff_can_be_configured_again_only_with_matching_proof() {
        let mut request = composed_request();
        request.intent = Some(extension_api::StreamIntent::Resume);
        let data = &mut request.dependency_inputs[0].data;
        data["control_state"] = json!("restored");
        data["snapshot_id"] = json!("snapshot-1");
        data["preservation_proof"] = json!({"kind":"mode_only_preserved","snapshot_id":"snapshot-1","before_digest":"a".repeat(64),"after_digest":"a".repeat(64)});
        let plan = plan_composed(&request).unwrap();
        assert_eq!(
            plan.control_proposals[0].arguments["operation"],
            "configure"
        );
        for (field, value) in [
            ("snapshot_id", json!(null)),
            ("snapshot_id", json!("")),
            ("snapshot_id", json!("x".repeat(129))),
            ("control_state", json!("configured")),
            ("control_state", json!("recovery_required")),
            ("preservation_proof", json!(null)),
            (
                "preservation_proof",
                json!({"kind":"mode_only_preserved","snapshot_id":"other","before_digest":"a".repeat(64),"after_digest":"a".repeat(64)}),
            ),
            (
                "preservation_proof",
                json!({"kind":"mode_only_preserved","snapshot_id":"snapshot-1","before_digest":"a".repeat(64),"after_digest":"b".repeat(64)}),
            ),
        ] {
            let mut invalid = request.clone();
            invalid.dependency_inputs[0].data[field] = value;
            assert_eq!(
                plan_composed(&invalid),
                Err("display_target_already_configured")
            );
        }
    }
    #[test]
    fn session_phases_do_not_configure_or_restore_stream_settings() {
        let mut request = composed_request();
        request.dependency_inputs.clear();
        request.target = serde_json::from_value(json!({"kind":"session","host_epoch":"epoch-1","session_id":"session-1","generation":1})).unwrap();
        for phase in [
            extension_api::LifecyclePhase::SessionPrepare,
            extension_api::LifecyclePhase::SessionRelease,
        ] {
            request.phase = phase;
            let plan = plan_composed(&request).unwrap();
            assert!(plan.control_proposals.is_empty());
            assert!(plan.obligations.is_empty());
        }
    }
    #[test]
    fn composed_plan_rejects_ambiguous_and_unverified_observations() {
        let mut request = composed_request();
        request
            .settings
            .insert("display_target".into(), json!("physical"));
        assert_eq!(
            plan_composed(&request),
            Err("display_target_kind_unverified")
        );
        request
            .settings
            .insert("display_target".into(), json!("virtual"));
        request
            .dependency_inputs
            .push(request.dependency_inputs[0].clone());
        assert!(plan_composed(&request).is_err());
        request.dependency_inputs.pop();
        request.dependency_inputs[0].data["mode"]["hdr"] = Value::Null;
        assert!(plan_composed(&request).is_ok());
        request.dependency_inputs[0].data["mode"]["hdr"] = json!(false);
        request.dependency_inputs[0].data["scale_percent"] = Value::Null;
        assert!(plan_composed(&request).is_ok());
        request.dependency_inputs[0].data["scale_percent"] = json!(100);
        request.dependency_inputs[0].domain_observations[0].domain = "other".into();
        assert_eq!(plan_composed(&request), Err("invalid_request"));
    }
    #[test]
    fn composed_physical_target_requires_matching_identity_or_observed_primary() {
        let mut request = composed_request();
        request
            .settings
            .insert("display_target".into(), json!("physical"));
        request.dependency_inputs[0].data["kind"] = json!("physical");
        request.dependency_inputs[0].data["physical_identity"] = json!("monitor-1");
        assert_eq!(plan_composed(&request), Err("physical_target_unavailable"));
        request.dependency_inputs[0].data["primary"] = json!(true);
        assert!(plan_composed(&request).is_ok());
        request
            .settings
            .insert("physical_target".into(), json!("identifier"));
        request
            .settings
            .insert("physical_display_id".into(), json!("monitor-2"));
        assert_eq!(plan_composed(&request), Err("physical_target_unavailable"));
        request
            .settings
            .insert("physical_display_id".into(), json!("monitor-1"));
        assert!(plan_composed(&request).is_ok());
    }
}
