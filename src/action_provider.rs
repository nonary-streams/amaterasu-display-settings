//! Planned action provider. This module is not a registered endpoint; the
//! runtime must supply durable receipts and an effect backend before enabling it.
use crate::{actions, descriptor};
use amaterasu_module_sdk::{
    Command, ModuleResult, Response,
    extension_api::{
        self, ActionTarget, ConsumerChange, MutationDomainPlan, PlannedResource, ResourceAccess,
        ResourceObligation, ResourcePlan,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const ACTION_CALLER: &str = "amaterasu.extension-actions";
const LIFECYCLE: &str = "amaterasu.session-lifecycle/1";
fn execute_method() -> Value {
    json!({"service":descriptor::SERVICE,"method":"action_execute","interface_major":1,"interface_minor":0,"schema_revision":1})
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRequest {
    pub version: u32,
    pub operation_id: String,
    pub action_id: String,
    pub target: ActionTarget,
    pub arguments: Value,
    pub expected_settings_revision: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    pub version: u32,
    pub operation_id: String,
    pub action_id: String,
    pub target: ActionTarget,
    pub arguments: Value,
    pub expected_settings_revision: Option<String>,
    pub plan: ResourcePlan,
    pub plan_digest: String,
    pub permit: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    pub version: u32,
    pub operation_id: String,
    pub action_id: String,
    pub target: ActionTarget,
    pub plan_digest: String,
    pub provider_receipt: Value,
}

/// Collected from the authenticated target's durable ownership journal and
/// provider inventory. The caller must verify freshness and target ownership.
pub struct TargetSnapshot {
    pub resource: PlannedResource,
    pub domain: MutationDomainPlan,
    pub obligations: Vec<ResourceObligation>,
    pub affected_consumers: Vec<String>,
    pub settings_revision: String,
    pub provider_constraints: Value,
}

pub fn plan(
    caller: &str,
    request: &PlanRequest,
    snapshot: TargetSnapshot,
    verify: impl FnOnce(&PlanRequest, &TargetSnapshot) -> bool,
) -> Result<ResourcePlan, &'static str> {
    if caller != ACTION_CALLER
        || request.version != 1
        || !valid_operation(&request.operation_id)
        || matches!(request.target, ActionTarget::Host { .. })
        || actions::parse_action(&request.action_id, request.arguments.clone()).is_err()
        || !verify(request, &snapshot)
    {
        return Err("unauthorized_or_invalid_action");
    }
    if snapshot.settings_revision.is_empty()
        || snapshot.resource.provider != descriptor::PROVIDER
        || snapshot.resource.access != ResourceAccess::Exclusive
        || snapshot.domain.access != ResourceAccess::Exclusive
        || !snapshot
            .resource
            .mutation_domains
            .contains(&snapshot.domain.domain)
        || snapshot.obligations.is_empty()
        || !snapshot.provider_constraints.is_object()
    {
        return Err("unavailable_target");
    }
    if snapshot.obligations.iter().any(|o| {
        o.provider != descriptor::PROVIDER || o.resource_id != snapshot.resource.resource_id
    }) {
        return Err("invalid_obligations");
    }
    let id_hash = format!("{:x}", Sha256::digest(request.operation_id.as_bytes()));
    let plan = ResourcePlan {
        plan_id: format!("action-{}", &id_hash[..32]),
        revision: 1,
        resources: vec![snapshot.resource],
        mutation_domains: vec![snapshot.domain],
        required_capabilities: vec![],
        constraints: json!({"action":{"operation_id":request.operation_id,"action_id":request.action_id,"target":request.target,"arguments":request.arguments,"expected_settings_revision":request.expected_settings_revision},"selected_settings_revision":snapshot.settings_revision,"provider":snapshot.provider_constraints}),
        obligations: snapshot.obligations,
        affected_consumers: snapshot.affected_consumers,
        consumer_change: ConsumerChange::ReconnectRequired,
        candidate_constraint: None,
        allowed_degradation: vec![],
    };
    extension_api::validate_resource_plan(&plan).map_err(|_| "invalid_plan")?;
    Ok(plan)
}

pub fn plan_digest(plan: &ResourcePlan) -> Result<String, &'static str> {
    extension_api::validate_resource_plan(plan).map_err(|_| "invalid_plan")?;
    let canonical = serde_json::to_value(plan).map_err(|_| "invalid_plan")?;
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical).map_err(|_| "invalid_plan")?)
    ))
}
fn valid_operation(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
}
fn request_matches(req: &ExecuteRequest) -> bool {
    if req.version != 1
        || !valid_operation(&req.operation_id)
        || req.permit.is_empty()
        || req.permit.len() > 512
        || req.permit.chars().any(char::is_control)
        || matches!(req.target, ActionTarget::Host { .. })
        || actions::parse_action(&req.action_id, req.arguments.clone()).is_err()
        || plan_digest(&req.plan).ok().as_deref() != Some(req.plan_digest.as_str())
    {
        return false;
    }
    if req
        .plan
        .constraints
        .get("selected_settings_revision")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return false;
    }
    req.plan.constraints.get("action")
        == Some(
            &json!({"operation_id":req.operation_id,"action_id":req.action_id,"target":req.target,"arguments":req.arguments,"expected_settings_revision":req.expected_settings_revision}),
        )
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ActionOutcome {
    Succeeded {
        receipt: Value,
    },
    Failed {
        cleanup_complete: bool,
        receipt: Value,
    },
    RecoveryRequired {
        receipt: Value,
    },
}
#[derive(Clone, Debug, PartialEq)]
pub enum StoreCommand {
    Begin {
        operation_id: String,
        request: Value,
    },
    Complete {
        operation_id: String,
        request: Value,
        outcome: ActionOutcome,
    },
    Lookup {
        request: StatusRequest,
    },
}
#[derive(Clone, Debug, PartialEq)]
pub enum StoreProgress {
    Waiting,
    Begun,
    Completed,
    ExistingPending,
    ExistingComplete(ActionOutcome),
    NotFound,
    Unknown,
}
/// Only durable acknowledgements are success. Existing pending must not replay.
pub trait ActionStore {
    fn poll(&mut self, command: &StoreCommand) -> StoreProgress;
}
#[derive(Clone, Debug, PartialEq)]
pub enum EffectProgress {
    Waiting,
    Succeeded(Value),
    FailedClean(Value),
    Unknown,
}
/// The backend must dispatch only the exact verified plan, preserve native
/// ownership, and be restart-reconcilable. An unknown outcome is never replayed.
pub trait EffectBackend {
    fn poll(&mut self, request: &ExecuteRequest) -> EffectProgress;
}
#[derive(Clone, Debug, PartialEq)]
pub enum Progress {
    Waiting,
    Complete(ActionOutcome),
    Rejected(&'static str),
    RecoveryRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Begin,
    Verify,
    Effect,
    Complete,
    Done,
}

pub struct ActionExecution {
    request: ExecuteRequest,
    request_value: Value,
    phase: Phase,
    verify: Command,
    broker_id: Option<u64>,
    verification: bool,
    failures: u8,
    outcome: Option<ActionOutcome>,
    deadline_ms: u64,
}
impl ActionExecution {
    pub fn new(
        caller: &str,
        request: ExecuteRequest,
        now_ms: u64,
        timeout_ms: u64,
    ) -> Result<Self, &'static str> {
        if caller != ACTION_CALLER
            || !request_matches(&request)
            || !(1..=30_000).contains(&timeout_ms)
        {
            return Err("invalid_action_execution");
        }
        let request_value = serde_json::to_value(&request).map_err(|_| "invalid_request")?;
        if serde_json::to_vec(&request_value)
            .map_err(|_| "invalid_request")?
            .len()
            > 12 * 1024
        {
            return Err("invalid_request");
        }
        let verify = Command::Request {
            service: LIFECYCLE.into(),
            payload: json!({"operation":"verify_action_effect","operation_id":request.operation_id,"action_id":request.action_id,"target":request.target,"plan_digest":request.plan_digest,"permit":request.permit,"provider":descriptor::PROVIDER,"execute_method":execute_method()}),
            timeout_ms,
            operation_id: format!(
                "action-verify.{:x}",
                Sha256::digest(request.operation_id.as_bytes())
            ),
            parent: None,
        };
        Ok(Self {
            request,
            request_value,
            phase: Phase::Begin,
            verify,
            broker_id: None,
            verification: false,
            failures: 0,
            outcome: None,
            deadline_ms: now_ms.saturating_add(timeout_ms),
        })
    }
    /// At most one store, coordinator or backend step per poll. A coordinator
    /// reply authorizes effects only after exact binding and retirement checks.
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
        store: &mut impl ActionStore,
        backend: &mut impl EffectBackend,
    ) -> Progress {
        if self.phase == Phase::Done {
            return self
                .outcome
                .clone()
                .map_or(Progress::RecoveryRequired, Progress::Complete);
        }
        if now_ms >= self.deadline_ms || self.failures >= 3 {
            return self.unknown();
        }
        match self.phase {
            Phase::Begin => match store.poll(&StoreCommand::Begin {
                operation_id: self.request.operation_id.clone(),
                request: self.request_value.clone(),
            }) {
                StoreProgress::Waiting => Progress::Waiting,
                StoreProgress::Begun => {
                    self.phase = Phase::Verify;
                    Progress::Waiting
                }
                StoreProgress::ExistingComplete(outcome) => {
                    self.outcome = Some(outcome.clone());
                    self.phase = Phase::Done;
                    Progress::Complete(outcome)
                }
                _ => self.unknown(),
            },
            Phase::Verify => self.poll_verify(send),
            Phase::Effect => match backend.poll(&self.request) {
                EffectProgress::Waiting => Progress::Waiting,
                EffectProgress::Succeeded(receipt) => {
                    self.finish_effect(ActionOutcome::Succeeded { receipt })
                }
                EffectProgress::FailedClean(receipt) => self.finish_effect(ActionOutcome::Failed {
                    cleanup_complete: true,
                    receipt,
                }),
                EffectProgress::Unknown => self.unknown(),
            },
            Phase::Complete => {
                let Some(outcome) = self.outcome.clone() else {
                    return self.unknown();
                };
                match store.poll(&StoreCommand::Complete {
                    operation_id: self.request.operation_id.clone(),
                    request: self.request_value.clone(),
                    outcome: outcome.clone(),
                }) {
                    StoreProgress::Waiting => Progress::Waiting,
                    StoreProgress::Completed => {
                        self.phase = Phase::Done;
                        Progress::Complete(outcome)
                    }
                    _ => self.unknown(),
                }
            }
            Phase::Done => unreachable!(),
        }
    }
    fn poll_verify(
        &mut self,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> Progress {
        if let Some(id) = self.broker_id {
            if self.verification {
                return match send(Command::ReleaseResult { request: id }) {
                    Ok(Response::Ok) => {
                        self.phase = Phase::Effect;
                        Progress::Waiting
                    }
                    _ => {
                        self.failures += 1;
                        Progress::Waiting
                    }
                };
            }
            match send(Command::TakeResult { request: id }) {
                Ok(Response::Pending) => Progress::Waiting,
                Ok(Response::Result { payload })
                    if payload.get("status").and_then(Value::as_str) == Some("succeeded")
                        && payload.get("operation_id").and_then(Value::as_str)
                            == Some(self.request.operation_id.as_str())
                        && payload.get("action_id").and_then(Value::as_str)
                            == Some(self.request.action_id.as_str())
                        && payload.get("plan_digest").and_then(Value::as_str)
                            == Some(self.request.plan_digest.as_str())
                        && payload.get("provider").and_then(Value::as_str)
                            == Some(descriptor::PROVIDER)
                        && payload.get("execute_method") == Some(&execute_method())
                        && payload.get("target") == Some(&json!(self.request.target)) =>
                {
                    self.verification = true;
                    Progress::Waiting
                }
                _ => self.unknown(),
            }
        } else {
            match send(self.verify.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.broker_id = Some(id);
                    Progress::Waiting
                }
                _ => {
                    self.failures += 1;
                    Progress::Waiting
                }
            }
        }
    }
    fn finish_effect(&mut self, outcome: ActionOutcome) -> Progress {
        let receipt = match &outcome {
            ActionOutcome::Succeeded { receipt }
            | ActionOutcome::Failed { receipt, .. }
            | ActionOutcome::RecoveryRequired { receipt } => receipt,
        };
        if !receipt.is_object()
            || serde_json::to_vec(receipt).map_or(true, |bytes| bytes.len() > 4096)
        {
            return self.unknown();
        }
        self.outcome = Some(outcome);
        self.phase = Phase::Complete;
        Progress::Waiting
    }
    fn unknown(&mut self) -> Progress {
        self.phase = Phase::Done;
        self.outcome = None;
        Progress::RecoveryRequired
    }
}

/// Status is lookup only: it never invokes the native effect or replays a call.
pub fn status(caller: &str, request: &StatusRequest, store: &mut impl ActionStore) -> Progress {
    if caller != ACTION_CALLER
        || request.version != 1
        || !valid_operation(&request.operation_id)
        || actions::parse_action(&request.action_id, json!({})).is_err()
            && request.action_id != actions::SET_MODE
        || request.plan_digest.len() != 64
        || !request
            .plan_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || matches!(request.target, ActionTarget::Host { .. })
        || !request.provider_receipt.is_object()
    {
        return Progress::Rejected("invalid_status");
    }
    match store.poll(&StoreCommand::Lookup {
        request: request.clone(),
    }) {
        StoreProgress::Waiting => Progress::Waiting,
        StoreProgress::ExistingComplete(result) => Progress::Complete(result),
        _ => Progress::RecoveryRequired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    fn request() -> PlanRequest {
        serde_json::from_value(json!({"version":1,"operation_id":"epoch:1","action_id":actions::REMOVE_OWNED,"target":{"kind":"stream","host_epoch":"epoch","session_id":"session","stream_id":"stream","expected_generation":1},"arguments":{},"expected_settings_revision":"settings-1"})).unwrap()
    }
    fn snapshot() -> TargetSnapshot {
        TargetSnapshot {resource:serde_json::from_value(json!({"provider":descriptor::PROVIDER,"resource_id":"resource-1","incarnation":"incarnation-1","expected_revision":1,"execution_domain":"desktop","mutation_domains":["domain-1"],"access":"exclusive"})).unwrap(),domain:serde_json::from_value(json!({"domain":"domain-1","expected_revision":4,"borrowers":{"stream":1},"access":"exclusive"})).unwrap(),obligations:vec![serde_json::from_value(json!({"obligation_id":"cleanup-1","provider":descriptor::PROVIDER,"resource_id":"resource-1","mutation_domain":"domain-1","depends_on":[],"cleanup_method":{"service":descriptor::SERVICE,"method":"lifecycle_callback","interface_major":1,"interface_minor":0,"schema_revision":1},"payload":{"identity":"resource-1"}})).unwrap()],affected_consumers:vec!["video".into()],settings_revision:"settings-1".into(),provider_constraints:json!({"identity":"resource-1"})}
    }
    fn execute() -> ExecuteRequest {
        let request = request();
        let plan = plan(ACTION_CALLER, &request, snapshot(), |_, _| true).unwrap();
        let digest = plan_digest(&plan).unwrap();
        ExecuteRequest {
            version: 1,
            operation_id: request.operation_id,
            action_id: request.action_id,
            target: request.target,
            arguments: request.arguments,
            expected_settings_revision: request.expected_settings_revision,
            plan,
            plan_digest: digest,
            permit: "permit-1".into(),
        }
    }
    struct Store {
        replies: VecDeque<StoreProgress>,
        calls: Vec<StoreCommand>,
    }
    impl ActionStore for Store {
        fn poll(&mut self, c: &StoreCommand) -> StoreProgress {
            self.calls.push(c.clone());
            self.replies.pop_front().unwrap()
        }
    }
    struct Backend {
        calls: usize,
    }
    impl EffectBackend for Backend {
        fn poll(&mut self, _: &ExecuteRequest) -> EffectProgress {
            self.calls += 1;
            EffectProgress::Succeeded(json!({"resource":"resource-1"}))
        }
    }
    fn verification(req: &ExecuteRequest) -> Value {
        json!({"status":"succeeded","operation_id":req.operation_id,"action_id":req.action_id,"target":req.target,"plan_digest":req.plan_digest,"provider":descriptor::PROVIDER,"execute_method":execute_method()})
    }
    #[test]
    fn successful_effect_follows_durable_receipt_and_exact_coordinator_verification() {
        let req = execute();
        let mut call = ActionExecution::new(ACTION_CALLER, req.clone(), 0, 100).unwrap();
        let mut store = Store {
            replies: VecDeque::from([StoreProgress::Begun, StoreProgress::Completed]),
            calls: vec![],
        };
        let mut backend = Backend { calls: 0 };
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 3 }),
            Ok(Response::Result {
                payload: verification(&req),
            }),
            Ok(Response::Ok),
        ]);
        let mut commands = Vec::new();
        let mut send = |c: Command| {
            commands.push(c);
            replies.pop_front().unwrap()
        };
        for tick in 1..=5 {
            assert_eq!(
                call.poll(tick, &mut send, &mut store, &mut backend),
                Progress::Waiting
            );
        }
        assert_eq!(
            call.poll(6, &mut send, &mut store, &mut backend),
            Progress::Complete(ActionOutcome::Succeeded {
                receipt: json!({"resource":"resource-1"})
            })
        );
        assert_eq!(backend.calls, 1);
        assert!(matches!(
            &store.calls[..],
            [StoreCommand::Begin { .. }, StoreCommand::Complete { .. }]
        ));
        match &commands[0] {
            Command::Request { payload, .. } => {
                assert_eq!(payload["operation"], "verify_action_effect");
                assert_eq!(payload["provider"], descriptor::PROVIDER);
                assert_eq!(payload["execute_method"], execute_method())
            }
            _ => panic!(),
        }
    }
    #[test]
    fn mismatched_verification_and_pending_receipt_never_invoke_effect() {
        let req = execute();
        let mut call = ActionExecution::new(ACTION_CALLER, req.clone(), 0, 100).unwrap();
        let mut store = Store {
            replies: VecDeque::from([StoreProgress::Begun]),
            calls: vec![],
        };
        let mut backend = Backend { calls: 0 };
        let mut reply = verification(&req);
        reply["target"]["stream_id"] = json!("other");
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 3 }),
            Ok(Response::Result { payload: reply }),
        ]);
        let mut send = |_: Command| replies.pop_front().unwrap();
        assert_eq!(
            call.poll(1, &mut send, &mut store, &mut backend),
            Progress::Waiting
        );
        assert_eq!(
            call.poll(2, &mut send, &mut store, &mut backend),
            Progress::Waiting
        );
        assert_eq!(
            call.poll(3, &mut send, &mut store, &mut backend),
            Progress::RecoveryRequired
        );
        assert_eq!(backend.calls, 0);
        let mut again = ActionExecution::new(ACTION_CALLER, req, 0, 100).unwrap();
        let mut store = Store {
            replies: VecDeque::from([StoreProgress::ExistingPending]),
            calls: vec![],
        };
        assert_eq!(
            again.poll(1, &mut send, &mut store, &mut backend),
            Progress::RecoveryRequired
        );
        assert_eq!(backend.calls, 0);
    }
    #[test]
    fn plan_and_execution_reject_unauthorized_or_tampered_requests() {
        let request = request();
        assert!(plan("unknown", &request, snapshot(), |_, _| true).is_err());
        let mut req = execute();
        req.arguments = json!({"new":"value"});
        assert!(ActionExecution::new(ACTION_CALLER, req, 0, 100).is_err());
        let mut req = execute();
        req.plan_digest = "0".repeat(64);
        assert!(ActionExecution::new(ACTION_CALLER, req, 0, 100).is_err());
    }

    #[test]
    fn canonical_digest_matches_shared_sorted_json_vector() {
        let plan: ResourcePlan = serde_json::from_value(json!({"plan_id":"p","revision":1,"resources":[],"mutation_domains":[],"required_capabilities":[],"constraints":{"z":1,"a":2},"obligations":[],"affected_consumers":[],"consumer_change":"reconnect_required","candidate_constraint":null,"allowed_degradation":[]})).unwrap();
        assert_eq!(
            plan_digest(&plan).unwrap(),
            "e45d56a17f9c2d75f55e5c408a1274f304a6437f3c01b5c785c619911f5ce73e"
        );
    }
}

/// Read-only planner: coordinator metadata, exact target journal and live
/// native borrow must all agree before an effect plan is returned.
pub struct ActionPlanner {
    request: PlanRequest,
    parent: u64,
    deadline_ms: u64,
    command: Command,
    broker_id: Option<u64>,
    reply: Option<Value>,
    failures: u8,
    phase: PlannerPhase,
    description: Option<PlannerDescription>,
    store: Option<crate::durable_store::VirtualDurableStateStore>,
    obligation: Option<crate::virtual_callback::VirtualObligation>,
    borrow: Option<crate::virtual_display::PendingCall>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlannerPhase {
    Describe,
    Load,
    Borrow,
    Done,
}
struct PlannerDescription {
    target: extension_api::LifecycleTarget,
    candidate: extension_api::CaptureBinding,
    settings_revision: String,
    domain: MutationDomainPlan,
    obligations: Vec<ResourceObligation>,
}
#[derive(Clone, Debug, PartialEq)]
pub enum ActionPlanProgress {
    Waiting,
    Planned(Box<ResourcePlan>),
    Rejected(&'static str),
    Unknown,
}
impl ActionPlanner {
    pub fn new(
        caller: &str,
        request: PlanRequest,
        parent: u64,
        now_ms: u64,
        timeout_ms: u64,
    ) -> Result<Self, &'static str> {
        if caller != ACTION_CALLER
            || request.version != 1
            || !valid_operation(&request.operation_id)
            || parent == 0
            || !(1..=30_000).contains(&timeout_ms)
            || actions::parse_action(&request.action_id, request.arguments.clone()).is_err()
            || matches!(request.target, ActionTarget::Host { .. })
        {
            return Err("invalid_action_plan");
        }
        // Replacement is not exposed until the coordinator supplies geometry
        // authority and the backend implements it.
        if request.action_id != actions::REMOVE_OWNED {
            return Err("action_unsupported");
        }
        let op = format!(
            "action-plan.{:x}",
            Sha256::digest(request.operation_id.as_bytes())
        );
        let command = Command::Request {
            service: LIFECYCLE.into(),
            payload: json!({"operation":"describe_action_target","target":request.target,"action_id":request.action_id,"operation_id":request.operation_id}),
            timeout_ms,
            operation_id: op,
            parent: Some(parent),
        };
        Ok(Self {
            request,
            parent,
            deadline_ms: now_ms.saturating_add(timeout_ms),
            command,
            broker_id: None,
            reply: None,
            failures: 0,
            phase: PlannerPhase::Describe,
            description: None,
            store: None,
            obligation: None,
            borrow: None,
        })
    }
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> ActionPlanProgress {
        if self.phase == PlannerPhase::Done {
            return ActionPlanProgress::Unknown;
        }
        if now_ms >= self.deadline_ms || self.failures >= 3 {
            self.phase = PlannerPhase::Done;
            return ActionPlanProgress::Unknown;
        }
        match self.phase {
            PlannerPhase::Describe => {
                if let Some(id) = self.broker_id {
                    if self.reply.is_some() {
                        match send(Command::ReleaseResult { request: id }) {
                            Ok(Response::Ok) => {
                                let payload = self.reply.take().expect("reply");
                                match parse_description(&self.request, &payload) {
                                    Ok(description) => {
                                        let target = &description.target;
                                        let epoch = match target {
                                            extension_api::LifecycleTarget::Stream {
                                                host_epoch,
                                                ..
                                            } => host_epoch.clone(),
                                            _ => {
                                                self.phase = PlannerPhase::Done;
                                                return ActionPlanProgress::Rejected(
                                                    "invalid_action_target",
                                                );
                                            }
                                        };
                                        let key = format!(
                                            "target-{:x}",
                                            Sha256::digest(
                                                serde_json::to_vec(target)
                                                    .expect("target serializes")
                                            )
                                        );
                                        let result = (|| {
                                            let epoch =
                                                crate::receipt_store::VerifiedEpoch::authenticate(
                                                    epoch,
                                                    |_| true,
                                                )?;
                                            let target =
                                                crate::durable_store::VerifiedTarget::authenticate(
                                                    key,
                                                    |_| true,
                                                )?;
                                            let mut store=crate::durable_store::VirtualDurableStateStore::new(epoch,target,format!("action-plan.{}",self.parent),Some(self.parent),self.deadline_ms.saturating_sub(now_ms).min(30_000))?;
                                            store.start_load()?;
                                            Ok::<_, &'static str>(store)
                                        })();
                                        match result {
                                            Ok(store) => {
                                                self.store = Some(store);
                                                self.description = Some(description);
                                                self.phase = PlannerPhase::Load;
                                                ActionPlanProgress::Waiting
                                            }
                                            Err(_) => {
                                                self.phase = PlannerPhase::Done;
                                                ActionPlanProgress::Unknown
                                            }
                                        }
                                    }
                                    Err(reason) => {
                                        self.phase = PlannerPhase::Done;
                                        ActionPlanProgress::Rejected(reason)
                                    }
                                }
                            }
                            _ => {
                                self.failures += 1;
                                ActionPlanProgress::Waiting
                            }
                        }
                    } else {
                        match send(Command::TakeResult { request: id }) {
                            Ok(Response::Pending) => ActionPlanProgress::Waiting,
                            Ok(Response::Result { payload }) => {
                                self.reply = Some(payload);
                                ActionPlanProgress::Waiting
                            }
                            _ => {
                                self.failures += 1;
                                ActionPlanProgress::Waiting
                            }
                        }
                    }
                } else {
                    match send(self.command.clone()) {
                        Ok(Response::Accepted { id }) => {
                            self.broker_id = Some(id);
                            ActionPlanProgress::Waiting
                        }
                        _ => {
                            self.failures += 1;
                            ActionPlanProgress::Waiting
                        }
                    }
                }
            }
            PlannerPhase::Load => {
                let store = self.store.as_mut().expect("store");
                store.advance(now_ms, send);
                match store.poll_load() {
                    crate::durable_store::LoadProgress::Waiting => ActionPlanProgress::Waiting,
                    crate::durable_store::LoadProgress::Found(obligation) => {
                        let Some(description) = self.description.as_ref() else {
                            self.phase = PlannerPhase::Done;
                            return ActionPlanProgress::Unknown;
                        };
                        if !obligation_matches(description, &obligation) {
                            self.phase = PlannerPhase::Done;
                            return ActionPlanProgress::Rejected("action_ownership_mismatch");
                        }
                        let Some(borrow) = obligation.borrow.as_ref() else {
                            self.phase = PlannerPhase::Done;
                            return ActionPlanProgress::Rejected("action_borrow_missing");
                        };
                        let request = crate::virtual_display::DisplayRequest::ValidateBorrow {
                            reference: crate::virtual_display::DisplayReference {
                                identity: obligation.identity.clone(),
                                reference_id: obligation.reference_id.clone(),
                            },
                            borrow_id: borrow.borrow_id.clone(),
                        };
                        match crate::virtual_display::PendingCall::new(
                            request,
                            format!(
                                "action-plan-borrow.{:x}",
                                Sha256::digest(self.request.operation_id.as_bytes())
                            ),
                            Some(self.parent),
                            self.deadline_ms.saturating_sub(now_ms).min(30_000),
                            now_ms,
                        ) {
                            Ok(call) => {
                                self.borrow = Some(call);
                                self.obligation = Some(obligation);
                                self.phase = PlannerPhase::Borrow;
                                ActionPlanProgress::Waiting
                            }
                            Err(_) => {
                                self.phase = PlannerPhase::Done;
                                ActionPlanProgress::Unknown
                            }
                        }
                    }
                    _ => {
                        self.phase = PlannerPhase::Done;
                        ActionPlanProgress::Unknown
                    }
                }
            }
            PlannerPhase::Borrow => {
                match self.borrow.as_mut().expect("borrow").poll(now_ms, send) {
                    crate::virtual_display::CallProgress::Waiting => ActionPlanProgress::Waiting,
                    crate::virtual_display::CallProgress::Complete(
                        crate::virtual_display::DisplayOutcome::Borrowed(current),
                    ) => {
                        let mut description = self.description.take().expect("description");
                        let obligation = self.obligation.take().expect("obligation");
                        let Some(saved) = obligation.borrow.as_ref() else {
                            self.phase = PlannerPhase::Done;
                            return ActionPlanProgress::Unknown;
                        };
                        if &current != saved
                            || current.mutation_domain.pending_mutations != 0
                            || usize::try_from(current.mutation_domain.borrowers).ok()
                                != Some(description.domain.borrowers.len())
                            || current.mutation_domain.revision
                                != description.domain.expected_revision
                        {
                            self.phase = PlannerPhase::Done;
                            return ActionPlanProgress::Rejected("action_domain_changed");
                        }
                        description.obligations.retain(|o| {
                            o.payload.get("identity").and_then(Value::as_str)
                                == Some(obligation.identity.as_str())
                                && o.payload.get("reference_id").and_then(Value::as_str)
                                    == Some(obligation.reference_id.as_str())
                        });
                        if description.obligations.is_empty() {
                            self.phase = PlannerPhase::Done;
                            return ActionPlanProgress::Rejected("action_obligation_missing");
                        }
                        let resource = PlannedResource {
                            provider: descriptor::PROVIDER.into(),
                            resource_id: description.candidate.resource.resource_id.clone(),
                            incarnation: Some(description.candidate.resource.incarnation.clone()),
                            expected_revision: Some(description.candidate.resource.revision),
                            execution_domain: description
                                .candidate
                                .resource
                                .execution_domain
                                .clone(),
                            mutation_domains: description
                                .candidate
                                .resource
                                .mutation_domains
                                .clone(),
                            access: ResourceAccess::Exclusive,
                        };
                        let snapshot = TargetSnapshot {
                            resource,
                            domain: description.domain,
                            obligations: description.obligations,
                            affected_consumers: vec![],
                            settings_revision: description.settings_revision,
                            provider_constraints: json!({"virtual":obligation,"lifecycle_target":description.target}),
                        };
                        self.phase = PlannerPhase::Done;
                        match plan(ACTION_CALLER, &self.request, snapshot, |_, _| true) {
                            Ok(plan) => ActionPlanProgress::Planned(Box::new(plan)),
                            Err(reason) => ActionPlanProgress::Rejected(reason),
                        }
                    }
                    _ => {
                        self.phase = PlannerPhase::Done;
                        ActionPlanProgress::Unknown
                    }
                }
            }
            PlannerPhase::Done => ActionPlanProgress::Unknown,
        }
    }
}

fn parse_description(
    request: &PlanRequest,
    payload: &Value,
) -> Result<PlannerDescription, &'static str> {
    if payload.get("status").and_then(Value::as_str) != Some("succeeded")
        || payload.get("provider").and_then(Value::as_str) != Some(descriptor::PROVIDER)
        || payload.get("target") != Some(&json!(request.target))
    {
        return Err("action_target_unavailable");
    }
    let streams = payload
        .get("streams")
        .and_then(Value::as_array)
        .ok_or("invalid_action_target")?;
    let active: Vec<_> = streams
        .iter()
        .filter(|s| s.get("phase").and_then(Value::as_str) == Some("active"))
        .collect();
    let [selected] = active.as_slice() else {
        return Err("action_target_ambiguous");
    };
    let target: extension_api::LifecycleTarget = serde_json::from_value(
        selected
            .get("lifecycle_target")
            .cloned()
            .ok_or("invalid_action_target")?,
    )
    .map_err(|_| "invalid_action_target")?;
    let selected_target: ActionTarget = serde_json::from_value(
        selected
            .get("target")
            .cloned()
            .ok_or("invalid_action_target")?,
    )
    .map_err(|_| "invalid_action_target")?;
    if !target_matches(&request.target, &selected_target, &target) {
        return Err("action_target_mismatch");
    }
    let candidate: extension_api::CaptureBinding = serde_json::from_value(
        selected
            .get("candidate")
            .cloned()
            .ok_or("invalid_action_target")?,
    )
    .map_err(|_| "invalid_action_target")?;
    if extension_api::validate_capture_binding(&candidate).is_err()
        || candidate.resource.provider != descriptor::PROVIDER
        || payload.get("execution_domain").and_then(Value::as_str)
            != Some(candidate.resource.execution_domain.as_str())
    {
        return Err("invalid_action_binding");
    }
    let domain_id = candidate
        .resource
        .mutation_domain
        .as_deref()
        .ok_or("action_domain_unavailable")?;
    if candidate.resource.mutation_domains.as_slice() != [domain_id] {
        return Err("action_domain_unavailable");
    }
    let domain_value = payload
        .get("mutation_domains")
        .and_then(|v| v.get(domain_id))
        .ok_or("action_domain_unavailable")?;
    let revision = domain_value
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or("action_domain_unavailable")?;
    let borrowers = serde_json::from_value(
        domain_value
            .get("borrowers")
            .cloned()
            .ok_or("action_domain_unavailable")?,
    )
    .map_err(|_| "action_domain_unavailable")?;
    let domain = MutationDomainPlan {
        domain: domain_id.into(),
        expected_revision: revision,
        borrowers,
        access: ResourceAccess::Exclusive,
    };
    let settings_revision = payload
        .get("settings_revision")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("settings_snapshot_missing")?
        .to_owned();
    let obligations: Vec<ResourceObligation> = serde_json::from_value(
        payload
            .get("obligations")
            .cloned()
            .ok_or("action_obligation_missing")?,
    )
    .map_err(|_| "action_obligation_missing")?;
    let obligations: Vec<_> = obligations
        .into_iter()
        .filter(|o| {
            o.provider == descriptor::PROVIDER
                && o.resource_id == candidate.resource.resource_id
                && o.mutation_domain.as_deref() == Some(domain_id)
        })
        .collect();
    if obligations.is_empty() {
        return Err("action_obligation_missing");
    }
    Ok(PlannerDescription {
        target,
        candidate,
        settings_revision,
        domain,
        obligations,
    })
}
pub(crate) fn target_matches(
    requested: &ActionTarget,
    selected: &ActionTarget,
    lifecycle: &extension_api::LifecycleTarget,
) -> bool {
    match (requested, selected, lifecycle) {
        (
            ActionTarget::Stream {
                host_epoch: a,
                session_id: b,
                stream_id: c,
                expected_generation: d,
            },
            ActionTarget::Stream {
                host_epoch: e,
                session_id: f,
                stream_id: g,
                expected_generation: h,
            },
            extension_api::LifecycleTarget::Stream {
                host_epoch: i,
                session_id: j,
                stream_id: k,
                generation: l,
            },
        ) => a == e && a == i && b == f && b == j && c == g && c == k && d == h && d == l,
        (
            ActionTarget::Session {
                host_epoch: a,
                session_id: b,
                ..
            },
            ActionTarget::Stream {
                host_epoch: e,
                session_id: f,
                stream_id: g,
                expected_generation: h,
            },
            extension_api::LifecycleTarget::Stream {
                host_epoch: i,
                session_id: j,
                stream_id: k,
                generation: l,
            },
        ) => a == e && a == i && b == f && b == j && g == k && h == l,
        _ => false,
    }
}
fn obligation_matches(
    description: &PlannerDescription,
    obligation: &crate::virtual_callback::VirtualObligation,
) -> bool {
    let Some(borrow) = obligation.borrow.as_ref() else {
        return false;
    };
    let binding = &description.candidate;
    obligation.provider_service == crate::virtual_display::SERVICE
        && !obligation.reference_released
        && binding.resource.resource_id == obligation.identity
        && binding.resource.incarnation
            == crate::virtual_callback::producer_incarnation(
                &obligation.domain_id,
                &obligation.identity,
                &borrow.observed_output,
            )
        && binding.resource.mutation_domain.as_deref() == Some(obligation.domain_id.as_str())
        && binding.resource.revision == borrow.mutation_domain.revision
        && binding.mode.width == obligation.width
        && binding.mode.height == obligation.height
        && binding.mode.refresh_millihz == obligation.refresh_millihz
        && binding.mode.hdr == obligation.hdr_enabled
        && binding.selector
            == json!({"output":format!("kwin:{}",borrow.observed_output.output_name)})
        && description.obligations.iter().any(|o| {
            o.payload.get("identity").and_then(Value::as_str) == Some(obligation.identity.as_str())
                && o.payload.get("reference_id").and_then(Value::as_str)
                    == Some(obligation.reference_id.as_str())
        })
}
