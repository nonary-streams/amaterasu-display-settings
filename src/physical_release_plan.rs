//! Read-only planning of physical lease cleanup from a durable owned journal.
use crate::{
    descriptor,
    physical_display::{self, Configuration, RecoveryObligation},
    resource_plan::PlanProgress,
};
use amaterasu_module_sdk::{
    Command, ModuleResult, Response,
    extension_api::{
        self, ConsumerChange, LifecyclePhase, MethodRef, MutationDomainPlan, PlannedResource,
        ProviderOperation, ProviderRequest, ProviderResponse, ResourceAccess, ResourceObligation,
        ResourcePlan,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Call only after the coordinator has authenticated this exact request and
/// supplied its previously admitted domains and the target's durable journal.
pub struct PhysicalReleasePlanner {
    request: ProviderRequest,
    prior: RecoveryObligation,
    parent: Option<u64>,
    deadline: u64,
    phase: u8,
    domain_revision: Option<u64>,
    exchange: Command,
    result_id: Option<u64>,
    result: Option<Value>,
    failures: u8,
    done: Option<PlanProgress>,
}
impl PhysicalReleasePlanner {
    pub fn new(
        caller: &str,
        request: ProviderRequest,
        prior: RecoveryObligation,
        admitted_domains: &[MutationDomainPlan],
        parent: Option<u64>,
        now: u64,
        verify_target: impl FnOnce(&ProviderRequest, &RecoveryObligation) -> bool,
    ) -> Result<Self, &'static str> {
        if caller != "amaterasu.session-lifecycle"
            || request.operation != ProviderOperation::ResourcePlan
            || !matches!(
                request.phase,
                LifecyclePhase::StreamRelease | LifecyclePhase::SessionRelease
            )
            || extension_api::validate_provider_request(&request).is_err()
            || !verify_target(&request, &prior)
        {
            return Err("unauthorized_or_invalid_release");
        }
        let domain = prior
            .mutation_domain_id
            .as_deref()
            .ok_or("missing_prior_domain")?;
        let revision = prior
            .mutation_domain_revision
            .ok_or("missing_prior_domain")?;
        if prior.restored
            || prior.lease.as_deref().is_none_or(|lease| {
                lease.is_empty()
                    || lease.len() > 256
                    || !lease.bytes().all(|b| b.is_ascii_graphic())
            })
            || RecoveryObligation::new(
                prior.operation_id.clone(),
                prior.configuration.clone(),
                prior.topology_revision.clone(),
            )
            .and_then(|p| p.with_domain(domain.into(), revision))
            .is_err()
            || !admitted_domains.iter().any(|d| {
                d.domain == domain
                    && d.expected_revision == revision
                    && d.access == ResourceAccess::Exclusive
            })
        {
            return Err("prior_obligation_not_admitted");
        }
        let timeout = request.remaining_ms.min(30_000);
        let exchange = command(
            &request,
            "status",
            json!({"action":"status"}),
            parent,
            timeout,
        );
        Ok(Self {
            request,
            prior,
            parent,
            deadline: now.saturating_add(timeout),
            phase: 0,
            domain_revision: None,
            exchange,
            result_id: None,
            result: None,
            failures: 0,
            done: None,
        })
    }
    pub fn poll(
        &mut self,
        now: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> PlanProgress {
        if let Some(done) = &self.done {
            return done.clone();
        }
        if now >= self.deadline || self.failures >= 3 {
            return self.finish(PlanProgress::Unknown);
        }
        if let Some(id) = self.result_id {
            if self.result.is_none() {
                match send(Command::TakeResult { request: id }) {
                    Ok(Response::Pending) => {}
                    Ok(Response::Result { payload }) => self.result = Some(payload),
                    _ => self.failures += 1,
                };
                return PlanProgress::Waiting;
            }
            if !matches!(
                send(Command::ReleaseResult { request: id }),
                Ok(Response::Ok)
            ) {
                self.failures += 1;
                return PlanProgress::Waiting;
            }
            let value = self.result.take().expect("checked result");
            return self.consume(value, now);
        }
        match send(self.exchange.clone()) {
            Ok(Response::Accepted { id }) => {
                self.result_id = Some(id);
                self.failures = 0;
            }
            _ => self.failures += 1,
        };
        PlanProgress::Waiting
    }
    fn consume(&mut self, value: Value, now: u64) -> PlanProgress {
        if self.phase == 0 {
            let domain = &value["mutation_domain"];
            let revision = domain["revision"].as_u64();
            if value["ok"] != true
                || value["native_supported"] != true
                || value["mutation_enabled"] != true
                || !matches!(
                    value["state"].as_str(),
                    Some("leased" | "recovery_required")
                )
                || value["owned_by_caller"] != true
                || value["lease"].as_str() != self.prior.lease.as_deref()
                || value["operation_id"].as_str() != Some(&self.prior.operation_id)
                || domain["id"].as_str() != self.prior.mutation_domain_id.as_deref()
                || domain["scope"] != "provider_lease_only"
                || domain["active_leases"] != 1
                || domain["external_borrowers_known"] != false
                || revision
                    .is_none_or(|r| r < self.prior.mutation_domain_revision.unwrap_or(u64::MAX))
            {
                return self.finish(rejected("physical_lease_unverified"));
            }
            self.domain_revision = revision;
            self.phase = 1;
            self.result_id = None;
            self.failures = 0;
            self.exchange = command(
                &self.request,
                "snapshot",
                json!({"action":"snapshot"}),
                self.parent,
                self.deadline.saturating_sub(now),
            );
            return PlanProgress::Waiting;
        }
        let current: Option<Configuration> =
            serde_json::from_value(value["configuration"].clone()).ok();
        let revision = value["topology_revision"].as_str();
        if value["ok"] != true
            || current.as_ref().is_none_or(|c| {
                c.validate().is_err()
                    || c.displays.len() != self.prior.configuration.displays.len()
                    || c.displays.iter().any(|d| {
                        !self
                            .prior
                            .configuration
                            .displays
                            .iter()
                            .any(|p| p.id == d.id)
                    })
            })
            || revision.is_none_or(|r| {
                r.len() != 32
                    || !r
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return self.finish(rejected("physical_snapshot_unverified"));
        }
        match self.plan(revision.expect("validated")) {
            Ok(plan) => self.finish(PlanProgress::Complete(Box::new(
                ProviderResponse::Planned { plan },
            ))),
            Err(reason) => self.finish(rejected(reason)),
        }
    }
    fn plan(&self, current_topology: &str) -> Result<ResourcePlan, &'static str> {
        let domain = self
            .prior
            .mutation_domain_id
            .as_ref()
            .ok_or("missing_domain")?;
        let resources = self
            .prior
            .configuration
            .displays
            .iter()
            .map(|d| PlannedResource {
                provider: descriptor::PROVIDER.into(),
                resource_id: d.id.clone(),
                incarnation: None,
                expected_revision: None,
                execution_domain: self.request.consumer_requirements.execution_domain.clone(),
                mutation_domains: vec![domain.clone()],
                access: ResourceAccess::Exclusive,
            })
            .collect();
        let obligations = self
            .prior
            .configuration
            .displays
            .iter()
            .map(|d| ResourceObligation {
                obligation_id: format!(
                    "physical-cleanup-{}",
                    stable_hex("physical-obligation", &d.id)
                ),
                provider: descriptor::PROVIDER.into(),
                resource_id: d.id.clone(),
                mutation_domain: Some(domain.clone()),
                depends_on: vec![],
                cleanup_method: MethodRef {
                    service: descriptor::SERVICE.into(),
                    method: "lifecycle_callback".into(),
                    interface_major: 1,
                    interface_minor: 0,
                    schema_revision: 1,
                },
                payload: json!({"service":physical_display::SERVICE,"identity":d.id}),
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
                domain: domain.clone(),
                expected_revision: self.domain_revision.ok_or("missing_domain")?,
                borrowers: BTreeMap::new(),
                access: ResourceAccess::Exclusive,
            }],
            required_capabilities: vec![],
            constraints: json!({"physical":{"provider":physical_display::SERVICE,"configuration":self.prior.configuration,"expected_topology_revision":self.prior.topology_revision,"expected_mutation_domain_id":domain,"expected_mutation_domain_revision":self.prior.mutation_domain_revision},"physical_release_observed_topology_revision":current_topology}),
            obligations,
            affected_consumers: vec![],
            consumer_change: ConsumerChange::ReconnectRequired,
            candidate_constraint: None,
            allowed_degradation: vec![],
        };
        extension_api::validate_resource_plan(&plan).map_err(|_| "invalid_resource_plan")?;
        Ok(plan)
    }
    fn finish(&mut self, value: PlanProgress) -> PlanProgress {
        self.done = Some(value.clone());
        value
    }
}
fn stable_hex(namespace: &str, value: &str) -> String {
    let input =
        serde_json::to_vec(&(descriptor::PROVIDER, namespace, value)).expect("strings serialize");
    format!("{:x}", Sha256::digest(input))[..32].into()
}
fn command(
    request: &ProviderRequest,
    label: &str,
    payload: Value,
    parent: Option<u64>,
    timeout: u64,
) -> Command {
    Command::Request {
        service: physical_display::SERVICE.into(),
        payload,
        timeout_ms: timeout,
        operation_id: format!(
            "display-plan.{}.{}",
            stable_hex("broker", &request.operation_id),
            label
        ),
        parent,
    }
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
    fn setup() -> (ProviderRequest, RecoveryObligation, Vec<MutationDomainPlan>) {
        let settings =
            amaterasu_configuration_schema::defaults(&crate::settings_schema::definitions())
                .unwrap();
        let request:ProviderRequest=serde_json::from_value(json!({"provider_sequence":8,"operation":"resource_plan","version":1,"transition_id":"transition-1","operation_id":"release-1","target":{"kind":"stream","host_epoch":"epoch-1","session_id":"session-1","stream_id":"stream-1","generation":1},"phase":"stream.release","settings_revision":"settings-1","settings":settings,"intent":null,"reason":"end","requested_video":null,"consumer_requirements":{"execution_domain":"desktop","capture_providers":["amaterasu.capture-pipewire/1"],"selector_schemas":["amaterasu.kwin-wl-output/1"]},"remaining_ms":5000,"plan_revision":null,"admission_id":null,"approved_plan":null})).unwrap();
        let configuration:Configuration=serde_json::from_value(json!({"displays":[{"id":"display-1","width":1920,"height":1080,"refresh":{"numerator":60,"denominator":1},"x":0,"y":0}]})).unwrap();
        let mut prior = RecoveryObligation::new(
            "apply-1".into(),
            configuration,
            "0123456789abcdef0123456789abcdef".into(),
        )
        .unwrap()
        .with_domain("physical_provider_session:abc".into(), 2)
        .unwrap();
        prior.lease = Some("lease-1".into());
        let domains = vec![MutationDomainPlan {
            domain: "physical_provider_session:abc".into(),
            expected_revision: 2,
            borrowers: BTreeMap::new(),
            access: ResourceAccess::Exclusive,
        }];
        (request, prior, domains)
    }
    fn status() -> Value {
        json!({"ok":true,"native_supported":true,"mutation_enabled":true,"state":"leased","owned_by_caller":true,"lease":"lease-1","operation_id":"apply-1","mutation_domain":{"id":"physical_provider_session:abc","revision":3,"active_leases":1,"scope":"provider_lease_only","external_borrowers_known":false}})
    }
    fn run(status: Value, snapshot: Value) -> (PlanProgress, Vec<Command>) {
        let (request, prior, domains) = setup();
        let mut planner = PhysicalReleasePlanner::new(
            "amaterasu.session-lifecycle",
            request,
            prior,
            &domains,
            Some(2),
            0,
            |_, _| true,
        )
        .unwrap();
        let mut responses = VecDeque::from([
            Ok(Response::Accepted { id: 1 }),
            Ok(Response::Result { payload: status }),
            Ok(Response::Ok),
            Ok(Response::Accepted { id: 2 }),
            Ok(Response::Result { payload: snapshot }),
            Ok(Response::Ok),
        ]);
        let mut commands = Vec::new();
        let mut result = PlanProgress::Waiting;
        for now in 0..6 {
            result = planner.poll(now, &mut |c| {
                commands.push(c);
                responses.pop_front().unwrap()
            });
            if result != PlanProgress::Waiting {
                break;
            }
        }
        (result, commands)
    }
    fn snapshot() -> Value {
        let (_, prior, _) = setup();
        json!({"ok":true,"configuration":prior.configuration,"topology_revision":"fedcba9876543210fedcba9876543210"})
    }
    #[test]
    fn release_plan_uses_saved_lease_and_current_separate_domain_and_snapshot() {
        let (progress, commands) = run(status(), snapshot());
        let PlanProgress::Complete(response) = progress else {
            panic!("no plan")
        };
        let ProviderResponse::Planned { plan } = *response else {
            panic!("rejected")
        };
        assert_eq!(plan.mutation_domains[0].expected_revision, 3);
        assert_eq!(
            plan.constraints["physical"]["expected_mutation_domain_revision"],
            2
        );
        assert_eq!(
            plan.constraints["physical"]["expected_topology_revision"],
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            plan.constraints["physical_release_observed_topology_revision"],
            "fedcba9876543210fedcba9876543210"
        );
        assert_eq!(plan.resources[0].provider, descriptor::PROVIDER);
        let calls: Vec<_> = commands
            .iter()
            .filter_map(|c| {
                if let Command::Request { payload, .. } = c {
                    Some(payload["action"].as_str().unwrap())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(calls, vec!["status", "snapshot"]);
    }
    #[test]
    fn wrong_lease_or_domain_and_missing_current_snapshot_fail_closed() {
        let mut wrong = status();
        wrong["lease"] = json!("other");
        assert!(
            matches!(run(wrong,snapshot()).0,PlanProgress::Complete(r) if matches!(*r,ProviderResponse::Rejected{..}))
        );
        let mut stale = status();
        stale["mutation_domain"]["revision"] = json!(1);
        assert!(
            matches!(run(stale,snapshot()).0,PlanProgress::Complete(r) if matches!(*r,ProviderResponse::Rejected{..}))
        );
        let mut missing = snapshot();
        missing["configuration"]["displays"][0]["id"] = json!("other");
        assert!(
            matches!(run(status(),missing).0,PlanProgress::Complete(r) if matches!(*r,ProviderResponse::Rejected{..}))
        );
        let (req, prior, mut domains) = setup();
        domains[0].expected_revision = 3;
        assert!(
            PhysicalReleasePlanner::new(
                "amaterasu.session-lifecycle",
                req,
                prior,
                &domains,
                None,
                0,
                |_, _| true
            )
            .is_err()
        );
    }
    #[test]
    fn transport_loss_never_returns_a_plan() {
        let (req, prior, domains) = setup();
        let mut planner = PhysicalReleasePlanner::new(
            "amaterasu.session-lifecycle",
            req,
            prior,
            &domains,
            None,
            0,
            |_, _| true,
        )
        .unwrap();
        for tick in 0..3 {
            assert_eq!(
                planner.poll(tick, &mut |_| Err("unavailable".into())),
                PlanProgress::Waiting
            );
        }
        assert_eq!(
            planner.poll(4, &mut |_| panic!("exhausted")),
            PlanProgress::Unknown
        );
    }
}
