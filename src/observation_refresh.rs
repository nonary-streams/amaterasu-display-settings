//! Read-only reconciliation of owned virtual borrows before coordinator refresh.
use crate::{
    descriptor,
    virtual_callback::VirtualObligation,
    virtual_display::{self, DisplayBorrow, DisplayReference, MutationDomain},
};
use amaterasu_module_sdk::{
    Command, ModuleResult, Response,
    extension_api::{
        LifecyclePhase, LifecycleTarget, MutationDomainPlan, ResourceObligation, ResourcePlan,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// This association must come from the selected coordinator's verified reply.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedPlan {
    pub admission_id: String,
    pub target: LifecycleTarget,
    pub phase: LifecyclePhase,
    pub plan: ResourcePlan,
}
/// Compare `before` exactly in durable state before persisting `observed`.
#[derive(Clone, Debug, PartialEq)]
pub struct JournalObservation {
    pub target: LifecycleTarget,
    pub before: VirtualObligation,
    pub observed: VirtualObligation,
}
#[derive(Clone, Debug, PartialEq)]
pub enum RefreshProgress {
    Waiting,
    Complete {
        domains: Vec<MutationDomainPlan>,
        journals: Vec<JournalObservation>,
    },
    Unknown,
}
struct Owned {
    target: LifecycleTarget,
    planned: VirtualObligation,
    execution_domain: String,
    refined_geometry: bool,
    journal: Option<VirtualObligation>,
    before: Option<VirtualObligation>,
}
pub struct ObservationRefresh {
    target: LifecycleTarget,
    operation_id: String,
    owned: Vec<Owned>,
    domain: Option<MutationDomain>,
    index: usize,
    phase: u8,
    command: Command,
    id: Option<u64>,
    result: Option<Value>,
    failures: u8,
    deadline: u64,
    parent: Option<u64>,
    done: Option<RefreshProgress>,
}
impl ObservationRefresh {
    /// `verify` authenticates the coordinator reply, exact target, plans and
    /// active obligations, including completeness of the retained plan list.
    pub fn new(
        target: LifecycleTarget,
        plans: Vec<AdmittedPlan>,
        obligations: Vec<ResourceObligation>,
        parent: Option<u64>,
        timeout: u64,
        now: u64,
        verify: impl FnOnce(&LifecycleTarget, &[AdmittedPlan], &[ResourceObligation]) -> bool,
    ) -> Result<Self, &'static str> {
        if timeout == 0
            || plans.is_empty()
            || plans.len() > 128
            || obligations.len() > 128
            || !verify(&target, &plans, &obligations)
        {
            return Err("unverified_observations");
        }
        let mut owned = Vec::new();
        let mut targets = BTreeSet::new();
        let mut refs = BTreeSet::new();
        for p in plans {
            if !matches!(
                p.phase,
                LifecyclePhase::SessionPrepare | LifecyclePhase::StreamPrepare
            ) {
                continue;
            }
            if !same_host_epoch(&target, &p.target)
                || p.admission_id.is_empty()
                || p.admission_id.len() > 128
                || amaterasu_module_sdk::extension_api::validate_resource_plan(&p.plan).is_err()
            {
                return Err("invalid_admitted_plan");
            }
            let planned: VirtualObligation = serde_json::from_value(
                p.plan
                    .constraints
                    .get("virtual_display")
                    .cloned()
                    .ok_or("unsupported_plan")?,
            )
            .map_err(|_| "unsupported_plan")?;
            if planned.provider_service != virtual_display::SERVICE
                || planned.reference_released
                || planned.borrow.is_some()
                || (DisplayReference {
                    identity: planned.identity.clone(),
                    reference_id: planned.reference_id.clone(),
                })
                .validate()
                .is_err()
            {
                return Err("invalid_virtual_plan");
            }
            let matching: Vec<_> = p
                .plan
                .resources
                .iter()
                .filter(|r| {
                    r.provider == descriptor::PROVIDER
                        && r.resource_id == planned.identity
                        && r.mutation_domains.contains(&planned.domain_id)
                })
                .collect();
            if matching.len() != 1
                || p.plan
                    .obligations
                    .iter()
                    .filter(|o| {
                        o.provider == descriptor::PROVIDER
                            && o.resource_id == planned.identity
                            && o.mutation_domain.as_deref() == Some(&planned.domain_id)
                            && o.payload.get("service") == Some(&json!(virtual_display::SERVICE))
                            && o.payload.get("identity") == Some(&json!(planned.identity))
                            && o.payload.get("reference_id") == Some(&json!(planned.reference_id))
                            && obligations.iter().any(|active| active == *o)
                    })
                    .count()
                    != 1
            {
                return Err("missing_owned_obligation");
            }
            let key = target_key(&p.target)?;
            if !targets.insert(key)
                || !refs.insert((planned.identity.clone(), planned.reference_id.clone()))
            {
                return Err("duplicate_owned_observation");
            }
            owned.push(Owned {
                target: p.target,
                planned,
                execution_domain: matching[0].execution_domain.clone(),
                refined_geometry: p
                    .plan
                    .constraints
                    .get("geometry_source")
                    .and_then(Value::as_str)
                    == Some("native_readback")
                    && p.plan.constraints.get("virtual_reconfigure").is_some(),
                journal: None,
                before: None,
            });
        }
        if owned.is_empty() {
            return Err("missing_live_prepare");
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| "random_unavailable")?;
        let operation_id = format!(
            "display-refresh-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let timeout = timeout.min(30_000);
        let command = make_command(
            virtual_display::SERVICE,
            json!({"action":"status"}),
            &operation_id,
            "status",
            parent,
            timeout,
        );
        Ok(Self {
            target,
            operation_id,
            owned,
            domain: None,
            index: 0,
            phase: 0,
            command,
            id: None,
            result: None,
            failures: 0,
            deadline: now.saturating_add(timeout),
            parent,
            done: None,
        })
    }
    pub fn poll(
        &mut self,
        now: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> RefreshProgress {
        if let Some(done) = &self.done {
            return done.clone();
        }
        if now >= self.deadline || self.failures >= 3 {
            return self.finish(RefreshProgress::Unknown);
        }
        if let Some(id) = self.id {
            if self.result.is_none() {
                match send(Command::TakeResult { request: id }) {
                    Ok(Response::Pending) => {}
                    Ok(Response::Result { payload }) => self.result = Some(payload),
                    _ => self.failures += 1,
                }
                return RefreshProgress::Waiting;
            }
            if !matches!(
                send(Command::ReleaseResult { request: id }),
                Ok(Response::Ok)
            ) {
                self.failures += 1;
                return RefreshProgress::Waiting;
            }
            let result = self.result.take().expect("checked");
            return self.consume(result, now);
        }
        match send(self.command.clone()) {
            Ok(Response::Accepted { id }) => {
                self.id = Some(id);
                self.failures = 0;
            }
            _ => self.failures += 1,
        }
        RefreshProgress::Waiting
    }
    fn issue(&mut self, service: &str, payload: Value, label: &str, now: u64) {
        self.command = make_command(
            service,
            payload,
            &self.operation_id,
            label,
            self.parent,
            self.deadline.saturating_sub(now),
        );
        self.id = None;
        self.failures = 0;
    }
    fn consume(&mut self, value: Value, now: u64) -> RefreshProgress {
        match self.phase {
            0 => {
                let domain: Option<MutationDomain> =
                    serde_json::from_value(value["mutation_domain"].clone()).ok();
                let Some(domain) = domain else {
                    return self.finish(RefreshProgress::Unknown);
                };
                if value["ok"] != true
                    || value["enabled"] != true
                    || value["native_supported"] != true
                    || value["recovery_ready"] != true
                    || domain.scope != "provider_session"
                    || domain.pending_mutations != 0
                    || domain.borrowers != self.owned.len() as u64
                    || self.owned.iter().any(|o| {
                        o.planned.domain_id != domain.id
                            || o.planned.domain_revision > domain.revision
                    })
                {
                    return self.finish(RefreshProgress::Unknown);
                }
                self.domain = Some(domain);
                self.phase = 1;
                self.issue_journal(now);
            }
            1 => {
                if value["ok"] != true || value["found"] != true {
                    return self.finish(RefreshProgress::Unknown);
                }
                let Ok(envelope) = crate::resize_store::decode_envelope(value["value"].clone())
                else {
                    return self.finish(RefreshProgress::Unknown);
                };
                let owned = &self.owned[self.index];
                let mut planned = owned.planned.clone();
                if owned.refined_geometry {
                    planned.geometry_revision = envelope.obligation.geometry_revision;
                }
                if !crate::virtual_callback::lineage_authorizes(&envelope, &owned.target, &planned)
                    || envelope.obligation.borrow.is_none()
                {
                    return self.finish(RefreshProgress::Unknown);
                }
                let saved = envelope.obligation;
                let borrow = saved.borrow.as_ref().expect("checked");
                let payload = json!({"action":"validate_borrow","identity":saved.identity,"reference_id":saved.reference_id,"borrow_id":borrow.borrow_id});
                self.owned[self.index].before = Some(saved.clone());
                self.owned[self.index].journal = Some(saved);
                self.phase = 2;
                self.issue(
                    virtual_display::SERVICE,
                    payload,
                    &format!("borrow-{}", self.index),
                    now,
                );
            }
            2 => {
                let saved = self.owned[self.index].journal.as_ref().expect("saved");
                let prior = saved.borrow.as_ref().expect("borrow");
                let observed: Option<DisplayBorrow> = (|| {
                    Some(DisplayBorrow {
                        borrow_id: value.get("borrow_id")?.as_str()?.into(),
                        observed_output: serde_json::from_value(
                            value.get("observed_output")?.clone(),
                        )
                        .ok()?,
                        mutation_domain: serde_json::from_value(
                            value.get("mutation_domain")?.clone(),
                        )
                        .ok()?,
                    })
                })();
                let Some(observed) = observed else {
                    return self.finish(RefreshProgress::Unknown);
                };
                if value["ok"] != true
                    || observed.borrow_id != prior.borrow_id
                    || observed.observed_output != prior.observed_output
                    || observed.mutation_domain != *self.domain.as_ref().expect("domain")
                    || observed.observed_output.width != saved.width
                    || observed.observed_output.height != saved.height
                    || observed.observed_output.refresh_millihz != saved.refresh_millihz
                {
                    return self.finish(RefreshProgress::Unknown);
                }
                self.owned[self.index]
                    .journal
                    .as_mut()
                    .expect("saved")
                    .borrow
                    .as_mut()
                    .expect("borrow")
                    .mutation_domain = observed.mutation_domain;
                self.index += 1;
                if self.index < self.owned.len() {
                    self.phase = 1;
                    self.issue_journal(now);
                } else {
                    let Some(payload) = self.refresh_payload() else {
                        return self.finish(RefreshProgress::Unknown);
                    };
                    self.phase = 3;
                    self.issue("amaterasu.session-lifecycle/1", payload, "refresh", now);
                }
            }
            3 => {
                if value["status"] != "succeeded"
                    || value["operation_id"] != self.operation_id
                    || value["target"] != json!(self.target)
                    || value["stale_mutation_domains"] != json!([])
                {
                    return self.finish(RefreshProgress::Unknown);
                }
                let Ok(domains) = serde_json::from_value::<Vec<MutationDomainPlan>>(
                    value["mutation_domains"].clone(),
                ) else {
                    return self.finish(RefreshProgress::Unknown);
                };
                let Some(payload) = self.refresh_payload() else {
                    return self.finish(RefreshProgress::Unknown);
                };
                let expected = &payload["domains"][0];
                if domains.len() != 1
                    || domains[0].domain != expected["domain"]
                    || domains[0].expected_revision
                        != expected["revision"].as_u64().unwrap_or(u64::MAX)
                    || json!(domains[0].borrowers) != expected["borrowers"]
                    || domains[0].access
                        != amaterasu_module_sdk::extension_api::ResourceAccess::Exclusive
                {
                    return self.finish(RefreshProgress::Unknown);
                }
                let journals = self
                    .owned
                    .iter()
                    .map(|o| JournalObservation {
                        target: o.target.clone(),
                        before: o.before.clone().expect("validated"),
                        observed: o.journal.clone().expect("validated"),
                    })
                    .collect();
                return self.finish(RefreshProgress::Complete { domains, journals });
            }
            _ => return self.finish(RefreshProgress::Unknown),
        }
        RefreshProgress::Waiting
    }
    fn issue_journal(&mut self, now: u64) {
        let key = target_key(&self.owned[self.index].target).expect("validated");
        self.issue(
            "amaterasu.state/1",
            json!({"action":"get","key":format!("virtual-obligation/v1/{key}")}),
            &format!("journal-{}", self.index),
            now,
        );
    }
    fn refresh_payload(&self) -> Option<Value> {
        let domain = self.domain.as_ref()?;
        let mut borrowers = BTreeMap::new();
        let mut resources = BTreeMap::new();
        let mut borrow_ids = BTreeSet::new();
        for stream in self.owned.iter().filter(|owned| owned.refined_geometry) {
            let LifecycleTarget::Stream {
                host_epoch,
                session_id,
                ..
            } = &stream.target
            else {
                return None;
            };
            let saved = stream.journal.as_ref()?;
            let session = self.owned.iter().find(|candidate| matches!(&candidate.target, LifecycleTarget::Session { host_epoch: epoch, session_id: id, .. } if epoch == host_epoch && id == session_id))?.journal.as_ref()?;
            let a = saved.borrow.as_ref()?;
            let b = session.borrow.as_ref()?;
            if saved.geometry_revision != session.geometry_revision
                || saved.width != session.width
                || saved.height != session.height
                || saved.refresh_millihz != session.refresh_millihz
                || crate::virtual_callback::producer_incarnation(
                    &saved.domain_id,
                    &saved.identity,
                    &a.observed_output,
                ) != crate::virtual_callback::producer_incarnation(
                    &session.domain_id,
                    &session.identity,
                    &b.observed_output,
                )
            {
                return None;
            }
        }
        for owned in &self.owned {
            let saved = owned.journal.as_ref()?;
            let borrow = saved.borrow.as_ref()?;
            let (borrower, generation) = borrower_identity(&owned.target)?;
            if !borrow_ids.insert(borrow.borrow_id.clone())
                || borrowers.insert(borrower.to_owned(), generation).is_some()
            {
                return None;
            }
            let incarnation = crate::virtual_callback::producer_incarnation(
                &domain.id,
                &saved.identity,
                &borrow.observed_output,
            );
            let resource = json!({"provider":descriptor::PROVIDER,"resource_id":saved.identity,"incarnation":incarnation,"revision":domain.revision,"execution_domain":owned.execution_domain,"mutation_domains":[domain.id]});
            if let Some(previous) = resources.insert(saved.identity.clone(), resource.clone())
                && previous != resource
            {
                return None;
            }
        }
        let resources: Vec<Value> = resources.into_values().collect();
        Some(
            json!({"operation":"refresh_provider_observations","operation_id":self.operation_id,"target":self.target,"domains":[{"domain":domain.id,"revision":domain.revision,"borrowers":borrowers}],"resources":resources}),
        )
    }
    fn finish(&mut self, value: RefreshProgress) -> RefreshProgress {
        self.done = Some(value.clone());
        value
    }
}
fn borrower_identity(target: &LifecycleTarget) -> Option<(&str, u64)> {
    match target {
        LifecycleTarget::Session {
            session_id,
            generation,
            ..
        } => Some((session_id, *generation)),
        LifecycleTarget::Stream {
            stream_id,
            generation,
            ..
        } => Some((stream_id, *generation)),
        _ => None,
    }
}
fn same_host_epoch(a: &LifecycleTarget, b: &LifecycleTarget) -> bool {
    fn epoch(t: &LifecycleTarget) -> Option<&str> {
        match t {
            LifecycleTarget::Session { host_epoch, .. }
            | LifecycleTarget::Stream { host_epoch, .. } => Some(host_epoch),
            _ => None,
        }
    }
    epoch(a).is_some() && epoch(a) == epoch(b)
}
fn target_key(target: &LifecycleTarget) -> Result<String, &'static str> {
    Ok(format!(
        "target-{:x}",
        Sha256::digest(serde_json::to_vec(target).map_err(|_| "invalid_target")?)
    ))
}
fn make_command(
    service: &str,
    payload: Value,
    id: &str,
    label: &str,
    parent: Option<u64>,
    timeout: u64,
) -> Command {
    Command::Request {
        service: service.into(),
        payload,
        operation_id: format!("{id}.{label}"),
        parent,
        timeout_ms: timeout.min(30_000),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "9c1d707f-7229-4fc4-b6e2-91f80c626a09";
    const DOMAIN: &str = "provider_session:abcdef";
    fn fixture() -> (
        LifecycleTarget,
        Vec<AdmittedPlan>,
        Vec<ResourceObligation>,
        VirtualObligation,
    ) {
        let target:LifecycleTarget=serde_json::from_value(json!({"kind":"stream","host_epoch":"epoch-1","session_id":"session-1","stream_id":"stream-1","generation":7})).unwrap();
        let saved:VirtualObligation=serde_json::from_value(json!({"provider_service":virtual_display::SERVICE,"identity":ID,"reference_id":"stream-1","width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false,"scale":null,"layout":"extended","domain_id":DOMAIN,"domain_revision":1,"geometry_revision":3,"borrow":{"borrow_id":"a".repeat(64),"observed_output":{"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1920,"height":1080,"refresh_millihz":60000},"mutation_domain":{"id":DOMAIN,"revision":2,"borrowers":1,"pending_mutations":0,"scope":"provider_session"}},"reference_released":false})).unwrap();
        let mut planned = saved.clone();
        planned.borrow = None;
        let plan:ResourcePlan=serde_json::from_value(json!({"plan_id":"plan-1","revision":1,"resources":[{"provider":descriptor::PROVIDER,"resource_id":ID,"incarnation":null,"expected_revision":null,"execution_domain":"desktop","mutation_domains":[DOMAIN],"access":"exclusive"}],"mutation_domains":[{"domain":DOMAIN,"expected_revision":1,"borrowers":{},"access":"exclusive"}],"required_capabilities":[],"constraints":{"virtual_display":planned},"obligations":[{"obligation_id":"cleanup-1","provider":descriptor::PROVIDER,"resource_id":ID,"mutation_domain":DOMAIN,"depends_on":[],"cleanup_method":{"service":descriptor::SERVICE,"method":"lifecycle_callback","interface_major":1,"interface_minor":0,"schema_revision":1},"payload":{"service":virtual_display::SERVICE,"identity":ID,"reference_id":"stream-1"}}],"affected_consumers":[],"consumer_change":"reconnect_required","candidate_constraint":null,"allowed_degradation":[]})).unwrap();
        (
            target.clone(),
            vec![AdmittedPlan {
                admission_id: "admission-1".into(),
                target,
                phase: LifecyclePhase::StreamPrepare,
                plan: plan.clone(),
            }],
            plan.obligations,
            saved,
        )
    }
    fn run(saved: VirtualObligation, count: u64) -> (RefreshProgress, Vec<Value>) {
        let (target, plans, obligations, _) = fixture();
        let mut machine =
            ObservationRefresh::new(target, plans, obligations, None, 5000, 0, |_, _, _| true)
                .unwrap();
        let mut reply = Value::Null;
        let mut calls = Vec::new();
        let mut n = 0;
        for now in 0..50 {
            let outcome=machine.poll(now,&mut |command|{match command {Command::Request{payload,..}=>{n+=1;calls.push(payload.clone());reply=match payload["action"].as_str(){Some("status")=>json!({"ok":true,"enabled":true,"native_supported":true,"recovery_ready":true,"mutation_domain":{"id":DOMAIN,"revision":2,"borrowers":count,"pending_mutations":0,"scope":"provider_session"}}),Some("get")=>json!({"ok":true,"found":true,"value":saved}),Some("validate_borrow")=>{let b=saved.borrow.clone().unwrap();json!({"ok":true,"borrow_id":b.borrow_id,"observed_output":b.observed_output,"mutation_domain":{"id":DOMAIN,"revision":2,"borrowers":count,"pending_mutations":0,"scope":"provider_session"}})},_=>json!({"status":"succeeded","operation_id":payload["operation_id"],"target":payload["target"],"mutation_domains":[{"domain":DOMAIN,"expected_revision":2,"borrowers":payload["domains"][0]["borrowers"],"access":"exclusive"}],"stale_mutation_domains":[]})};Ok(Response::Accepted{id:n})},Command::TakeResult{..}=>Ok(Response::Result{payload:reply.clone()}),Command::ReleaseResult{..}=>Ok(Response::Ok),_=>panic!("unexpected")}});
            if outcome != RefreshProgress::Waiting {
                return (outcome, calls);
            }
        }
        panic!("stuck")
    }
    #[test]
    fn refresh_requires_exact_state_and_native_borrow_before_coordinator() {
        let (_, _, _, mut saved) = fixture();
        saved.borrow.as_mut().unwrap().mutation_domain.revision = 1;
        let (result, calls) = run(saved, 1);
        assert!(
            matches!(result, RefreshProgress::Complete { ref journals, .. } if journals[0].observed.borrow.as_ref().unwrap().mutation_domain.revision == 2 && journals[0].before.borrow.as_ref().unwrap().mutation_domain.revision == 1)
        );
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[3]["domains"][0]["borrowers"]["stream-1"], 7);
    }
    #[test]
    fn unmatched_native_borrower_or_journal_never_refreshes() {
        let (_, _, _, saved) = fixture();
        let (result, calls) = run(saved.clone(), 2);
        assert_eq!(result, RefreshProgress::Unknown);
        assert_eq!(calls.len(), 1);
        let mut wrong = saved;
        wrong.width = 1280;
        let (result, calls) = run(wrong, 1);
        assert_eq!(result, RefreshProgress::Unknown);
        assert_eq!(calls.len(), 2);
    }
    #[test]
    fn duplicated_plans_or_untrusted_metadata_are_rejected() {
        let (target, plans, obligations, _) = fixture();
        let mut duplicate = plans.clone();
        duplicate.extend(plans.clone());
        assert!(
            ObservationRefresh::new(
                target.clone(),
                duplicate,
                obligations.clone(),
                None,
                5000,
                0,
                |_, _, _| true
            )
            .is_err()
        );
        assert!(
            ObservationRefresh::new(target, plans, obligations, None, 5000, 0, |_, _, _| false)
                .is_err()
        );
    }
    #[test]
    fn shared_output_validates_each_borrow_and_deduplicates_resource() {
        let (target, mut plans, mut obligations, mut first) = fixture();
        first.borrow.as_mut().unwrap().mutation_domain.borrowers = 2;
        let mut second = first.clone();
        second.reference_id = "stream-2".into();
        second.borrow.as_mut().unwrap().borrow_id = "c".repeat(64);
        let mut second_plan = plans[0].clone();
        second_plan.target=serde_json::from_value(json!({"kind":"stream","host_epoch":"epoch-1","session_id":"session-2","stream_id":"stream-2","generation":9})).unwrap();
        second_plan.admission_id = "admission-2".into();
        second_plan.plan.plan_id = "plan-2".into();
        second_plan.plan.constraints["virtual_display"]["reference_id"] = json!("stream-2");
        second_plan.plan.obligations[0].obligation_id = "cleanup-2".into();
        second_plan.plan.obligations[0].payload["reference_id"] = json!("stream-2");
        obligations.push(second_plan.plan.obligations[0].clone());
        plans.push(second_plan.clone());
        let key1 = format!("virtual-obligation/v1/{}", target_key(&target).unwrap());
        let key2 = format!(
            "virtual-obligation/v1/{}",
            target_key(&second_plan.target).unwrap()
        );
        let mut machine =
            ObservationRefresh::new(target, plans, obligations, None, 5000, 0, |_, _, _| true)
                .unwrap();
        let mut reply = Value::Null;
        let mut calls = Vec::new();
        let mut n = 0;
        for now in 0..80 {
            let outcome=machine.poll(now,&mut |command| match command {
                Command::Request{payload,..}=>{n+=1;calls.push(payload.clone());reply=match payload["action"].as_str(){
                    Some("status")=>json!({"ok":true,"enabled":true,"native_supported":true,"recovery_ready":true,"mutation_domain":{"id":DOMAIN,"revision":2,"borrowers":2,"pending_mutations":0,"scope":"provider_session"}}),
                    Some("get")=>{let saved=if payload["key"]==key1 {&first} else if payload["key"]==key2 {&second} else {panic!("wrong key")};json!({"ok":true,"found":true,"value":saved})},
                    Some("validate_borrow")=>{let saved=if payload["reference_id"]=="stream-1" {&first}else{&second};let b=saved.borrow.as_ref().unwrap();json!({"ok":true,"borrow_id":b.borrow_id,"observed_output":b.observed_output,"mutation_domain":b.mutation_domain})},
                    _=>json!({"status":"succeeded","operation_id":payload["operation_id"],"target":payload["target"],"mutation_domains":[{"domain":DOMAIN,"expected_revision":2,"borrowers":payload["domains"][0]["borrowers"],"access":"exclusive"}],"stale_mutation_domains":[]})};Ok(Response::Accepted{id:n})},
                Command::TakeResult{..}=>Ok(Response::Result{payload:reply.clone()}),Command::ReleaseResult{..}=>Ok(Response::Ok),_=>panic!("unexpected") });
            if outcome != RefreshProgress::Waiting {
                assert!(matches!(outcome, RefreshProgress::Complete { .. }));
                let refresh = calls.last().unwrap();
                assert_eq!(refresh["resources"].as_array().unwrap().len(), 1);
                assert_eq!(
                    refresh["domains"][0]["borrowers"],
                    json!({"stream-1":7,"stream-2":9})
                );
                return;
            }
        }
        panic!("stuck")
    }
    #[test]
    fn refined_stream_geometry_requires_matching_session_readback() {
        let (target, plans, obligations, saved) = fixture();
        let mut machine =
            ObservationRefresh::new(target, plans, obligations, None, 5000, 0, |_, _, _| true)
                .unwrap();
        machine.owned[0].refined_geometry = true;
        machine.owned[0].journal = Some(saved.clone());
        let mut session = saved.clone();
        session.reference_id = "session-ref".into();
        session.borrow.as_mut().unwrap().borrow_id = "c".repeat(64);
        machine.owned.push(Owned { target: serde_json::from_value(json!({"kind":"session","host_epoch":"epoch-1","session_id":"session-1","generation":1})).unwrap(), planned: session.clone(), execution_domain:"desktop".into(), refined_geometry:false, journal:Some(session), before:None });
        machine.domain = Some(MutationDomain {
            id: DOMAIN.into(),
            revision: 2,
            borrowers: 2,
            pending_mutations: 0,
            scope: "provider_session".into(),
        });
        assert!(machine.refresh_payload().is_some());
        machine.owned[1].journal.as_mut().unwrap().geometry_revision += 1;
        assert!(machine.refresh_payload().is_none());
    }
    #[test]
    fn release_plans_are_not_live_ownership_evidence() {
        let (target, plans, obligations, _) = fixture();
        let mut release = plans[0].clone();
        release.phase = LifecyclePhase::StreamRelease;
        let wire = serde_json::to_value(&release).unwrap();
        assert_eq!(wire["phase"], "stream.release");
        let parsed: AdmittedPlan = serde_json::from_value(wire).unwrap();
        assert!(
            ObservationRefresh::new(
                target.clone(),
                vec![parsed.clone()],
                obligations.clone(),
                None,
                5000,
                0,
                |_, _, _| true
            )
            .is_err()
        );
        let mut mixed = plans;
        mixed.push(parsed);
        assert!(
            ObservationRefresh::new(target, mixed, obligations, None, 5000, 0, |_, _, _| true)
                .is_ok()
        );
    }
}
