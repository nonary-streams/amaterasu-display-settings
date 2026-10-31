//! Validate coordinator-confirmed controls before acknowledging display settings.
//!
//! The coordinator authenticates admission, durably records obligations, and
//! invokes the owner. This module never invokes a native resource provider.
use amaterasu_module_sdk::extension_api::{
    self, CleanupOutcome, CleanupState, LifecyclePhase, LifecycleTarget, ProviderOperation,
    ProviderRequest, ProviderResponse, ResourceAccess, ResourceOutput,
};

/// The caller must first authenticate the coordinator and the exact admission.
/// Unconfirmed or mismatched effects are never acknowledged as cleanup.
pub fn composition_callback(request: &ProviderRequest) -> Result<ProviderResponse, &'static str> {
    if request.version != extension_api::COMPOSITION_VERSION
        || request.operation != ProviderOperation::LifecycleCallback
        || extension_api::validate_provider_request(request).is_err()
    {
        return Err("invalid_composition_callback");
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
        return Err("phase_target_mismatch");
    }
    let plan = request.approved_plan.as_ref().ok_or("missing_plan")?;
    if plan.control_proposals.len() != request.control_results.len() {
        return Err("unconfirmed_control");
    }
    let preparing = matches!(
        request.phase,
        LifecyclePhase::SessionPrepare | LifecyclePhase::StreamPrepare
    );
    if plan.control_proposals.len() != plan.obligations.len() {
        return Err("unconfirmed_obligation");
    }
    let mut proposal_ids = std::collections::BTreeSet::new();
    for proposal in &plan.control_proposals {
        if !proposal_ids.insert(&proposal.proposal_id) {
            return Err("duplicate_control");
        }
        let obligations: Vec<_> = plan
            .obligations
            .iter()
            .filter(|obligation| {
                obligation.provider == crate::descriptor::PROVIDER
                    && obligation.resource_id == proposal.resource.resource_id
                    && obligation.cleanup_method.service == crate::descriptor::SERVICE
                    && obligation.cleanup_method.method == "lifecycle_callback"
                    && obligation.cleanup_method.interface_major == 2
                    && obligation.cleanup_method.interface_minor == 0
                    && obligation.cleanup_method.schema_revision == 1
                    && obligation.payload.get("output_id").and_then(|v| v.as_str())
                        == Some(proposal.output_id.as_str())
                    && obligation
                        .mutation_domain
                        .as_ref()
                        .is_some_and(|domain| proposal.mutation_domains.contains(domain))
            })
            .collect();
        if obligations.len() != 1 {
            return Err("control_obligation_mismatch");
        }
        let mut inputs = request
            .dependency_inputs
            .iter()
            .filter(|input| input.output_id == proposal.output_id);
        let input = inputs.next().ok_or("missing_control_input")?;
        if inputs.next().is_some()
            || proposal.target != request.target
            || input.capability != "amaterasu.display-target"
            || proposal.owner_provider != input.producer
            || proposal.owner_service != input.producer_service
            || proposal.resource != input.resource
            || proposal.method.service != input.producer_service
            || proposal.method.method != "resource_control"
            || proposal.method.interface_major != 2
            || proposal.method.interface_minor != 0
            || proposal.method.schema_revision != 1
            || proposal.access != ResourceAccess::Exclusive
            || input.schema.id != "amaterasu.display-target/1"
            || input.schema.major != 1
            || input.schema.minor != 0
            || input.schema.digest
                != "ededc620113268bcae3990d492deeef039c5e9c5ff28067a676dd992fe6324ce"
            || proposal.argument_schema.id != "amaterasu.display-control/1"
            || proposal.argument_schema.major != 1
            || proposal.argument_schema.minor != 0
            || proposal.argument_schema.digest
                != "c2c3ce866277cb29bbd9fbd947899917538d46b1020df3197fbd264159607d87"
        {
            return Err("control_input_mismatch");
        }
        let mut results = request
            .control_results
            .iter()
            .filter(|result| result.proposal_id == proposal.proposal_id);
        let result = results.next().ok_or("unconfirmed_control")?;
        if results.next().is_some()
            || result.candidate.is_some()
            || !same_resource_output(input, &result.output)
        {
            return Err("control_result_mismatch");
        }
        let operation = proposal.arguments.get("operation").and_then(|v| v.as_str());
        let state = result
            .output
            .data
            .get("control_state")
            .and_then(|v| v.as_str());
        let snapshot = result
            .output
            .data
            .get("snapshot_id")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty() && v.len() <= 128)
            .ok_or("missing_control_snapshot")?;
        if preparing {
            if operation != Some("configure")
                || state != Some("configured")
                || result
                    .output
                    .data
                    .get("native_state")
                    .and_then(|v| v.as_str())
                    != Some("active")
                || !matches_requested_mode(&proposal.arguments, &input.data, &result.output.data)
            {
                return Err("configuration_not_confirmed");
            }
        } else if operation != Some("restore")
            || state != Some("restored")
            || proposal
                .arguments
                .get("snapshot_id")
                .and_then(|v| v.as_str())
                != Some(snapshot)
            || input.data.get("snapshot_id").and_then(|v| v.as_str()) != Some(snapshot)
        {
            return Err("restore_not_confirmed");
        }
    }
    let response = if preparing {
        ProviderResponse::Prepared {
            candidate: None,
            obligations: plan.obligations.clone(),
            outputs: vec![],
        }
    } else {
        ProviderResponse::Cleanup {
            outcomes: plan
                .obligations
                .iter()
                .map(|obligation| CleanupOutcome {
                    obligation_id: obligation.obligation_id.clone(),
                    state: CleanupState::Released,
                    reason: None,
                })
                .collect(),
            outputs: vec![],
        }
    };
    extension_api::validate_provider_response(request, &response)
        .map_err(|_| "invalid_callback_response")?;
    Ok(response)
}

fn same_resource_output(input: &ResourceOutput, result: &ResourceOutput) -> bool {
    input.output_id == result.output_id
        && input.capability == result.capability
        && input.schema == result.schema
        && input.producer == result.producer
        && input.producer_service == result.producer_service
        && input.origin == result.origin
        && input.resource.provider == result.resource.provider
        && input.resource.resource_id == result.resource.resource_id
        && input.resource.incarnation == result.resource.incarnation
        && input.resource.execution_domain == result.resource.execution_domain
        && input.resource.mutation_domain == result.resource.mutation_domain
        && input.resource.mutation_domains == result.resource.mutation_domains
        && result.resource.revision >= input.resource.revision
        && input.domain_observations.len() == result.domain_observations.len()
        && input.domain_observations.iter().all(|prior| {
            prior.complete
                && result.domain_observations.iter().any(|current| {
                    current.complete
                        && current.domain == prior.domain
                        && current.revision >= prior.revision
                })
        })
}

fn matches_requested_mode(
    arguments: &serde_json::Value,
    input: &serde_json::Value,
    output: &serde_json::Value,
) -> bool {
    let Some(mode) = output.get("mode") else {
        return false;
    };
    for field in ["width", "height", "refresh_millihz"] {
        if arguments
            .get(field)
            .and_then(|v| v.as_u64())
            .filter(|v| *v > 0)
            != mode.get(field).and_then(|v| v.as_u64())
        {
            return false;
        }
    }
    let proof = valid_preservation_proof(output);
    let hdr_matches = match arguments.get("hdr").and_then(|v| v.as_str()) {
        Some("preserve") => preserved(
            input.pointer("/mode/hdr").and_then(|v| v.as_bool()),
            mode.get("hdr").and_then(|v| v.as_bool()),
            proof,
        ),
        Some("on") => mode.get("hdr").and_then(|v| v.as_bool()) == Some(true),
        Some("off") => mode.get("hdr").and_then(|v| v.as_bool()) == Some(false),
        _ => false,
    };
    let scaling_matches = match arguments.pointer("/scaling/mode").and_then(|v| v.as_str()) {
        Some("preserve") => preserved(
            input.get("scale_percent").and_then(|v| v.as_u64()),
            output.get("scale_percent").and_then(|v| v.as_u64()),
            proof,
        ),
        Some("percent") => arguments
            .pointer("/scaling/percent")
            .and_then(|v| v.as_u64())
            .is_some_and(|percent| {
                output.get("scale_percent").and_then(|v| v.as_u64()) == Some(percent)
            }),
        _ => false,
    };
    let layout_matches = match arguments.get("layout").and_then(|v| v.as_str()) {
        Some("preserve") => preserved(
            input.get("layout").and_then(|v| v.as_str()),
            output.get("layout").and_then(|v| v.as_str()),
            proof,
        ),
        Some(layout) => output.get("layout").and_then(|v| v.as_str()) == Some(layout),
        _ => false,
    };
    hdr_matches && scaling_matches && layout_matches
}

fn preserved<T: PartialEq>(before: Option<T>, after: Option<T>, proof: bool) -> bool {
    match (before, after) {
        (Some(before), Some(after)) => before == after,
        _ => proof,
    }
}

fn valid_preservation_proof(output: &serde_json::Value) -> bool {
    let Some(proof) = output.get("preservation_proof") else {
        return false;
    };
    let Some(snapshot) = output
        .get("snapshot_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return false;
    };
    let Some(digest) = proof.get("before_digest").and_then(|v| v.as_str()) else {
        return false;
    };
    proof.get("kind").and_then(|v| v.as_str()) == Some("mode_only_preserved")
        && proof.get("snapshot_id").and_then(|v| v.as_str()) == Some(snapshot)
        && digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && proof.get("after_digest").and_then(|v| v.as_str()) == Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> ProviderRequest {
        let target = json!({"kind":"stream","host_epoch":"epoch-1","session_id":"session-1","stream_id":"stream-1","generation":1});
        let resource = json!({"provider":"example.screen","resource_id":"screen-1","incarnation":"inc-1","revision":1,"execution_domain":"desktop","mutation_domain":"domain-1","mutation_domains":["domain-1"]});
        let schema = json!({"id":"amaterasu.display-target/1","major":1,"minor":0,"digest":"ededc620113268bcae3990d492deeef039c5e9c5ff28067a676dd992fe6324ce"});
        let data = json!({"control_state":"configured","native_state":"active","snapshot_id":"snapshot-1","mode":{"width":1920,"height":1080,"refresh_millihz":60000,"hdr":false},"scale_percent":150,"layout":"extended"});
        let input = json!({"output_id":"output-1","capability":"amaterasu.display-target","schema":schema,"producer":"example.screen","producer_service":"example.screen/2","origin":target,"resource":resource,"domain_observations":[{"domain":"domain-1","revision":1,"borrowers":{},"complete":true}],"data":data});
        let proposal = json!({"proposal_id":"proposal-1","output_id":"output-1","owner_provider":"example.screen","owner_service":"example.screen/2","target":target,"resource":resource,"method":{"service":"example.screen/2","method":"resource_control","interface_major":2,"interface_minor":0,"schema_revision":1},"argument_schema":{"id":"amaterasu.display-control/1","major":1,"minor":0,"digest":"c2c3ce866277cb29bbd9fbd947899917538d46b1020df3197fbd264159607d87"},"arguments":{"operation":"configure","width":1920,"height":1080,"refresh_millihz":60000,"hdr":"off","scaling":{"mode":"percent","percent":150},"layout":"extended"},"access":"exclusive","mutation_domains":["domain-1"]});
        serde_json::from_value(json!({"provider_sequence":1,"operation":"lifecycle_callback","version":2,"transition_id":"transition-1","operation_id":"operation-1","target":target,"phase":"stream.prepare","settings_revision":"settings-1","settings":{},"intent":"initial","reason":null,"requested_video":null,"consumer_requirements":{"execution_domain":"desktop","capture_providers":["example.capture/1"],"selector_schemas":["example.selector/1"]},"remaining_ms":5000,"plan_revision":1,"admission_id":"admission-1","approved_plan":{"plan_id":"plan-1","revision":1,"resources":[{"provider":"example.screen","resource_id":"screen-1","incarnation":"inc-1","expected_revision":1,"execution_domain":"desktop","mutation_domains":["domain-1"],"access":"exclusive"}],"mutation_domains":[{"domain":"domain-1","expected_revision":1,"borrowers":{},"access":"exclusive"}],"required_capabilities":[],"constraints":{},"obligations":[{"obligation_id":"cleanup-1","provider":"nonary.display-settings","resource_id":"screen-1","mutation_domain":"domain-1","depends_on":[],"cleanup_method":{"service":"nonary.display-settings/2","method":"lifecycle_callback","interface_major":2,"interface_minor":0,"schema_revision":1},"payload":{"output_id":"output-1"}}],"affected_consumers":[],"consumer_change":"live","candidate_constraint":null,"allowed_degradation":[],"control_proposals":[proposal]},"dependency_inputs":[input],"control_results":[{"proposal_id":"proposal-1","output":input,"candidate":null}]})).unwrap()
    }

    #[test]
    fn control_confirmation_and_restore_are_fenced() {
        let mut request = fixture();
        assert!(matches!(
            composition_callback(&request),
            Ok(ProviderResponse::Prepared { .. })
        ));
        request.control_results.clear();
        assert!(composition_callback(&request).is_err());
        let mut request = fixture();
        request.control_results[0].output.resource.incarnation = "other".into();
        assert!(composition_callback(&request).is_err());
        let mut request = fixture();
        request.control_results[0].output.domain_observations[0].complete = false;
        assert!(composition_callback(&request).is_err());
        let mut request = fixture();
        request.phase = LifecyclePhase::StreamRelease;
        request.approved_plan.as_mut().unwrap().control_proposals[0].arguments =
            json!({"operation":"restore","snapshot_id":"snapshot-1"});
        request.control_results[0].output.data["control_state"] = json!("restored");
        assert!(matches!(
            composition_callback(&request),
            Ok(ProviderResponse::Cleanup { .. })
        ));
        request.control_results[0].output.data["snapshot_id"] = json!("other");
        assert!(composition_callback(&request).is_err());
    }

    #[test]
    fn requested_changes_require_observed_values() {
        let arguments = json!({"width":1920,"height":1080,"refresh_millihz":60000,"hdr":"off","scaling":{"mode":"percent","percent":150},"layout":"extended"});
        let mut output = json!({"mode":{"width":1920,"height":1080,"refresh_millihz":60000,"hdr":false},"scale_percent":150,"layout":"extended"});
        let input = output.clone();
        assert!(matches_requested_mode(&arguments, &input, &output));
        output["scale_percent"] = serde_json::Value::Null;
        assert!(!matches_requested_mode(&arguments, &input, &output));
        output["scale_percent"] = json!(150);
        output["mode"]["hdr"] = serde_json::Value::Null;
        assert!(!matches_requested_mode(&arguments, &input, &output));
        output["mode"]["hdr"] = json!(false);
        output["layout"] = json!("exclusive");
        assert!(!matches_requested_mode(&arguments, &input, &output));
    }

    #[test]
    fn preserved_values_must_be_observed_unchanged() {
        let mut request = fixture();
        request.approved_plan.as_mut().unwrap().control_proposals[0].arguments = json!({"operation":"configure","width":1920,"height":1080,"refresh_millihz":60000,"hdr":"preserve","scaling":{"mode":"preserve"},"layout":"preserve"});
        assert!(composition_callback(&request).is_ok());
        for (field, changed) in [
            ("hdr", json!(true)),
            ("scale_percent", json!(200)),
            ("layout", json!("exclusive")),
        ] {
            let mut altered = request.clone();
            if field == "hdr" {
                altered.control_results[0].output.data["mode"][field] = changed;
            } else {
                altered.control_results[0].output.data[field] = changed;
            }
            assert_eq!(
                composition_callback(&altered),
                Err("configuration_not_confirmed")
            );
        }
        request.dependency_inputs[0].data["scale_percent"] = serde_json::Value::Null;
        request.control_results[0].output.data["scale_percent"] = serde_json::Value::Null;
        assert_eq!(
            composition_callback(&request),
            Err("configuration_not_confirmed")
        );
        let proof = json!({"kind":"mode_only_preserved","snapshot_id":"snapshot-1","before_digest":"a".repeat(64),"after_digest":"a".repeat(64)});
        request.control_results[0].output.data["preservation_proof"] = proof.clone();
        assert!(composition_callback(&request).is_ok());
        request.control_results[0].output.data["mode"]["hdr"] = json!(true);
        assert_eq!(
            composition_callback(&request),
            Err("configuration_not_confirmed")
        );
        request.control_results[0].output.data["mode"]["hdr"] = json!(false);
        for (field, invalid) in [
            ("snapshot_id", json!("other")),
            ("before_digest", json!("A".repeat(64))),
            ("after_digest", json!("b".repeat(64))),
        ] {
            request.control_results[0].output.data["preservation_proof"] = proof.clone();
            request.control_results[0].output.data["preservation_proof"][field] = invalid;
            assert_eq!(
                composition_callback(&request),
                Err("configuration_not_confirmed")
            );
        }
    }

    #[test]
    fn session_callbacks_accept_an_admitted_noop() {
        let mut request = fixture();
        let plan = request.approved_plan.as_mut().unwrap();
        plan.control_proposals.clear();
        plan.obligations.clear();
        request.control_results.clear();
        request.dependency_inputs.clear();
        request.target = serde_json::from_value(json!({"kind":"session","host_epoch":"epoch-1","session_id":"session-1","generation":1})).unwrap();
        request.phase = LifecyclePhase::SessionPrepare;
        assert!(matches!(
            composition_callback(&request),
            Ok(ProviderResponse::Prepared { .. })
        ));
        request.phase = LifecyclePhase::SessionRelease;
        assert!(matches!(
            composition_callback(&request),
            Ok(ProviderResponse::Cleanup { .. })
        ));
    }
}
