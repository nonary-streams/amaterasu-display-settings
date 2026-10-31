//! Coordinator-admitted resize of an exact session-owned virtual display.
//! The store must journal the transition and CAS the canonical session record.
use crate::virtual_callback::{GuardProgress, VirtualObligation};
use crate::virtual_display::{
    self as wire, CallProgress, DisplayBorrow, DisplayOutcome, DisplayReference, DisplayRequest,
};
use amaterasu_module_sdk::{
    Command, ModuleResult, Response,
    extension_api::{
        LifecyclePhase, LifecycleTarget, ProviderOperation, ProviderRequest, VideoMode,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResizeIntent {
    pub request: ProviderRequest,
    pub session_target: LifecycleTarget,
    pub prior: VirtualObligation,
    pub desired: VideoMode,
    pub operation_id: String,
}
#[derive(Clone, Debug, PartialEq)]
pub enum ResizeStoreCommand {
    Begin {
        intent: ResizeIntent,
    },
    Commit {
        intent: ResizeIntent,
        updated: VirtualObligation,
    },
    Finish {
        intent: ResizeIntent,
        updated: VirtualObligation,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResizeStoreProgress {
    Waiting,
    Applied,
    ExistingPending,
    Unknown,
}
/// Begin persists the immutable intent and verifies the exact prior session
/// obligation. Commit atomically replaces that obligation while retaining the
/// intent. Finish durably records completion only after revalidation.
pub trait ResizeStore {
    fn poll(&mut self, command: &ResizeStoreCommand) -> ResizeStoreProgress;
}
/// Revalidates coordinator admission, exact selected plan, live request and
/// retirement of all affected consumers immediately before native submission.
pub trait ResizeGuard {
    fn poll(
        &mut self,
        intent: &ResizeIntent,
        parent: u64,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> GuardProgress;
}
#[derive(Clone, Debug, PartialEq)]
pub enum ResizeProgress {
    Waiting,
    Complete(Box<VirtualObligation>),
    RecoveryRequired,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Begin,
    Guard,
    Native,
    Commit,
    Validate,
    GuardFinish,
    Finish,
    GuardPublish,
    Done,
}
pub struct SessionResize {
    intent: ResizeIntent,
    phase: Phase,
    parent: u64,
    deadline: u64,
    nonce: String,
    serial: u32,
    call: Option<wire::PendingCall>,
    updated: Option<VirtualObligation>,
    committed: bool,
}
impl SessionResize {
    /// `verify` must authenticate the coordinator-selected canonical session,
    /// complete admitted plan and retirement evidence. Payload fields do not
    /// themselves establish that authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        caller: &str,
        request: ProviderRequest,
        session_target: LifecycleTarget,
        prior: VirtualObligation,
        desired: VideoMode,
        parent: u64,
        now_ms: u64,
        verify: impl FnOnce(&ProviderRequest, &LifecycleTarget, &VirtualObligation, &VideoMode) -> bool,
    ) -> Result<Self, &'static str> {
        let matches_session = matches!((&request.target, &session_target), (LifecycleTarget::Stream { host_epoch:a, session_id:b, .. }, LifecycleTarget::Session { host_epoch:c, session_id:d, generation }) if a == c && b == d && *generation != 0);
        let borrow = prior.borrow.as_ref().ok_or("missing_session_borrow")?;
        if caller != "amaterasu.session-lifecycle"
            || request.operation != ProviderOperation::LifecycleCallback
            || request.phase != LifecyclePhase::StreamPrepare
            || !request.approved_plan.as_ref().is_some_and(|plan| {
                plan.constraints.get("virtual_reconfigure")
                    == Some(
                        &json!({"session_target":session_target,"prior":prior,"desired":desired}),
                    )
            })
            || !matches_session
            || request.remaining_ms == 0
            || prior.reference_released
            || prior.provider_service != wire::SERVICE
            || desired.hdr != prior.hdr_enabled
            || !(320..=7680).contains(&desired.width)
            || !(200..=4320).contains(&desired.height)
            || !(1000..=1_000_000).contains(&desired.refresh_millihz)
            || borrow.mutation_domain.id != prior.domain_id
            || borrow.mutation_domain.scope != "provider_session"
            || borrow.mutation_domain.borrowers != 1
            || borrow.mutation_domain.pending_mutations != 0
            || borrow.observed_output.width != prior.width
            || borrow.observed_output.height != prior.height
            || borrow.observed_output.refresh_millihz != prior.refresh_millihz
            || !verify(&request, &session_target, &prior, &desired)
        {
            return Err("resize_admission_unverified");
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| "random_unavailable")?;
        let nonce: String = random.iter().map(|v| format!("{v:02x}")).collect();
        let operation_id = format!("resize.{nonce}");
        let timeout = request.remaining_ms.min(30_000);
        Ok(Self {
            intent: ResizeIntent {
                request,
                session_target,
                prior,
                desired,
                operation_id,
            },
            phase: Phase::Begin,
            parent,
            deadline: now_ms.saturating_add(timeout),
            nonce,
            serial: 0,
            call: None,
            updated: None,
            committed: false,
        })
    }
    pub fn intent(&self) -> &ResizeIntent {
        &self.intent
    }
    fn unknown(&mut self) -> ResizeProgress {
        self.phase = Phase::Done;
        ResizeProgress::RecoveryRequired
    }
    fn next_call(
        &mut self,
        request: DisplayRequest,
        now_ms: u64,
    ) -> Result<wire::PendingCall, &'static str> {
        self.serial = self.serial.checked_add(1).ok_or("operation_limit")?;
        let timeout = self.deadline.saturating_sub(now_ms).min(30_000);
        wire::PendingCall::new(
            request,
            format!("resize.{}.{}", self.nonce, self.serial),
            Some(self.parent),
            timeout,
            now_ms,
        )
    }
    fn reference(&self) -> DisplayReference {
        DisplayReference {
            identity: self.intent.prior.identity.clone(),
            reference_id: self.intent.prior.reference_id.clone(),
        }
    }
    fn new_obligation(&self, borrow: DisplayBorrow) -> Option<VirtualObligation> {
        let old = self.intent.prior.borrow.as_ref()?;
        let mode = &self.intent.desired;
        if borrow.borrow_id == old.borrow_id
            || borrow.mutation_domain.id != old.mutation_domain.id
            || borrow.mutation_domain.scope != "provider_session"
            || borrow.mutation_domain.borrowers != 1
            || borrow.mutation_domain.pending_mutations != 0
            || borrow.mutation_domain.revision <= old.mutation_domain.revision
            || borrow.observed_output.compositor_id != old.observed_output.compositor_id
            || borrow.observed_output.registry_global != old.observed_output.registry_global
            || borrow.observed_output.output_name != old.observed_output.output_name
            || crate::virtual_callback::producer_incarnation(
                &self.intent.prior.domain_id,
                &self.intent.prior.identity,
                &borrow.observed_output,
            ) != crate::virtual_callback::producer_incarnation(
                &self.intent.prior.domain_id,
                &self.intent.prior.identity,
                &old.observed_output,
            )
            || borrow.observed_output.width != mode.width
            || borrow.observed_output.height != mode.height
            || borrow.observed_output.refresh_millihz != mode.refresh_millihz
        {
            return None;
        }
        let mut updated = self.intent.prior.clone();
        updated.width = mode.width;
        updated.height = mode.height;
        updated.refresh_millihz = mode.refresh_millihz;
        updated.geometry_revision = borrow.mutation_domain.revision;
        updated.borrow = Some(borrow);
        Some(updated)
    }
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
        store: &mut impl ResizeStore,
        guard: &mut impl ResizeGuard,
    ) -> ResizeProgress {
        if now_ms >= self.deadline || self.phase == Phase::Done {
            return self.unknown();
        }
        match self.phase {
            Phase::Begin => match store.poll(&ResizeStoreCommand::Begin {
                intent: self.intent.clone(),
            }) {
                ResizeStoreProgress::Waiting => ResizeProgress::Waiting,
                ResizeStoreProgress::Applied => {
                    self.phase = Phase::Guard;
                    ResizeProgress::Waiting
                }
                _ => self.unknown(),
            },
            Phase::Guard => match guard.poll(&self.intent, self.parent, now_ms, send) {
                GuardProgress::Waiting => ResizeProgress::Waiting,
                GuardProgress::Authorized => {
                    self.phase = Phase::Native;
                    ResizeProgress::Waiting
                }
                _ => self.unknown(),
            },
            Phase::Native => {
                if self.call.is_none() {
                    let prior = self.intent.prior.borrow.as_ref().expect("validated borrow");
                    let request = DisplayRequest::Reconfigure {
                        reference: self.reference(),
                        operation_id: self.intent.operation_id.clone(),
                        borrow_id: prior.borrow_id.clone(),
                        width: self.intent.desired.width,
                        height: self.intent.desired.height,
                        refresh_millihz: self.intent.desired.refresh_millihz,
                        domain_id: prior.mutation_domain.id.clone(),
                        revision: prior.mutation_domain.revision,
                    };
                    self.call = match self.next_call(request, now_ms) {
                        Ok(c) => Some(c),
                        Err(_) => return self.unknown(),
                    };
                }
                if let Some(DisplayOutcome::Borrowed(borrow)) =
                    self.call.as_ref().and_then(|c| c.tentative())
                    && !self.committed
                {
                    let Some(updated) = self.new_obligation(borrow.clone()) else {
                        return self.unknown();
                    };
                    self.updated = Some(updated);
                    self.phase = Phase::Commit;
                    return ResizeProgress::Waiting;
                }
                if self
                    .call
                    .as_ref()
                    .is_some_and(|call| call.request_id().is_none())
                {
                    match guard.poll(&self.intent, self.parent, now_ms, send) {
                        GuardProgress::Waiting => return ResizeProgress::Waiting,
                        GuardProgress::Authorized => {}
                        _ => return self.unknown(),
                    }
                }
                match self.call.as_mut().expect("call").poll(now_ms, send) {
                    CallProgress::Waiting => ResizeProgress::Waiting,
                    CallProgress::Complete(DisplayOutcome::ReconfigurePending) => {
                        self.call = None;
                        self.phase = Phase::Guard;
                        ResizeProgress::Waiting
                    }
                    CallProgress::Complete(DisplayOutcome::Borrowed(_)) if self.committed => {
                        self.call = None;
                        self.phase = Phase::Validate;
                        ResizeProgress::Waiting
                    }
                    _ => self.unknown(),
                }
            }
            Phase::Commit => {
                let updated = self.updated.as_ref().expect("updated").clone();
                match store.poll(&ResizeStoreCommand::Commit {
                    intent: self.intent.clone(),
                    updated,
                }) {
                    ResizeStoreProgress::Waiting => ResizeProgress::Waiting,
                    ResizeStoreProgress::Applied => {
                        self.committed = true;
                        self.phase = Phase::Native;
                        ResizeProgress::Waiting
                    }
                    _ => self.unknown(),
                }
            }
            Phase::Validate => {
                if self.call.is_none() {
                    let borrow = self
                        .updated
                        .as_ref()
                        .and_then(|v| v.borrow.as_ref())
                        .expect("updated borrow");
                    let request = DisplayRequest::ValidateBorrow {
                        reference: self.reference(),
                        borrow_id: borrow.borrow_id.clone(),
                    };
                    self.call = match self.next_call(request, now_ms) {
                        Ok(c) => Some(c),
                        Err(_) => return self.unknown(),
                    };
                }
                match self.call.as_mut().expect("call").poll(now_ms, send) {
                    CallProgress::Waiting => ResizeProgress::Waiting,
                    CallProgress::Complete(DisplayOutcome::Borrowed(b))
                        if self.updated.as_ref().and_then(|v| v.borrow.as_ref()) == Some(&b) =>
                    {
                        self.call = None;
                        self.phase = Phase::GuardFinish;
                        ResizeProgress::Waiting
                    }
                    _ => self.unknown(),
                }
            }
            Phase::GuardFinish => match guard.poll(&self.intent, self.parent, now_ms, send) {
                GuardProgress::Waiting => ResizeProgress::Waiting,
                GuardProgress::Authorized => {
                    self.phase = Phase::Finish;
                    ResizeProgress::Waiting
                }
                _ => self.unknown(),
            },
            Phase::Finish => {
                let updated = self.updated.as_ref().expect("updated").clone();
                match store.poll(&ResizeStoreCommand::Finish {
                    intent: self.intent.clone(),
                    updated: updated.clone(),
                }) {
                    ResizeStoreProgress::Waiting => ResizeProgress::Waiting,
                    ResizeStoreProgress::Applied => {
                        self.phase = Phase::GuardPublish;
                        ResizeProgress::Waiting
                    }
                    _ => self.unknown(),
                }
            }
            Phase::GuardPublish => match guard.poll(&self.intent, self.parent, now_ms, send) {
                GuardProgress::Waiting => ResizeProgress::Waiting,
                GuardProgress::Authorized => {
                    self.phase = Phase::Done;
                    ResizeProgress::Complete(Box::new(
                        self.updated.as_ref().expect("updated").clone(),
                    ))
                }
                _ => self.unknown(),
            },
            Phase::Done => self.unknown(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::{cell::Cell, collections::BTreeMap, rc::Rc};
    struct Store {
        old: VirtualObligation,
        intent: Option<ResizeIntent>,
        updated: Option<VirtualObligation>,
        committed: Rc<Cell<bool>>,
        fail_commit: bool,
    }
    impl ResizeStore for Store {
        fn poll(&mut self, command: &ResizeStoreCommand) -> ResizeStoreProgress {
            match command {
                ResizeStoreCommand::Begin { intent }
                    if self.intent.is_none() && self.old == intent.prior =>
                {
                    self.intent = Some(intent.clone());
                    ResizeStoreProgress::Applied
                }
                ResizeStoreCommand::Commit { intent, updated }
                    if self.intent.as_ref() == Some(intent) && !self.fail_commit =>
                {
                    self.updated = Some(updated.clone());
                    self.committed.set(true);
                    ResizeStoreProgress::Applied
                }
                ResizeStoreCommand::Finish { intent, updated }
                    if self.intent.as_ref() == Some(intent)
                        && self.updated.as_ref() == Some(updated) =>
                {
                    ResizeStoreProgress::Applied
                }
                _ => ResizeStoreProgress::Unknown,
            }
        }
    }
    struct Guard(bool);
    impl ResizeGuard for Guard {
        fn poll(
            &mut self,
            _: &ResizeIntent,
            _: u64,
            _: u64,
            _: &mut impl FnMut(Command) -> ModuleResult<Response>,
        ) -> GuardProgress {
            if self.0 {
                GuardProgress::Authorized
            } else {
                GuardProgress::Rejected
            }
        }
    }
    fn fixture() -> (
        ProviderRequest,
        LifecycleTarget,
        VirtualObligation,
        VideoMode,
    ) {
        let mut request:ProviderRequest=serde_json::from_value(json!({"provider_sequence":2,"operation":"lifecycle_callback","version":1,"transition_id":"transition","operation_id":"op-2","target":{"kind":"stream","host_epoch":"epoch","session_id":"session","stream_id":"stream","generation":2},"phase":"stream.prepare","settings_revision":"settings","settings":{},"intent":"resume","reason":null,"requested_video":{"width":1280,"height":720,"refresh_millihz":60000,"hdr":false},"consumer_requirements":{"execution_domain":"desktop","capture_providers":["capture"],"selector_schemas":["schema"]},"remaining_ms":5000,"plan_revision":1,"admission_id":"admission","approved_plan":null})).unwrap();
        let session: LifecycleTarget = serde_json::from_value(
            json!({"kind":"session","host_epoch":"epoch","session_id":"session","generation":1}),
        )
        .unwrap();
        let old:VirtualObligation=serde_json::from_value(json!({"provider_service":wire::SERVICE,"identity":"11111111-1111-4111-8111-111111111111","reference_id":"ref-1","width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false,"scale":null,"layout":"extended","domain_id":"provider_session:abcdef","domain_revision":1,"geometry_revision":1,"borrow":{"borrow_id":"a".repeat(64),"observed_output":{"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1920,"height":1080,"refresh_millihz":60000},"mutation_domain":{"id":"provider_session:abcdef","revision":3,"borrowers":1,"pending_mutations":0,"scope":"provider_session"}},"reference_released":false})).unwrap();
        let desired = VideoMode {
            width: 1280,
            height: 720,
            refresh_millihz: 60000,
            hdr: false,
        };
        request.approved_plan = Some(serde_json::from_value(json!({"plan_id":"plan","revision":1,"resources":[],"mutation_domains":[],"required_capabilities":[],"constraints":{"virtual_reconfigure":{"session_target":session,"prior":old,"desired":desired}},"obligations":[],"affected_consumers":[],"consumer_change":"reconnect_required","candidate_constraint":null,"allowed_degradation":[]})).unwrap());
        (request, session, old, desired)
    }
    #[test]
    fn changed_mode_is_journaled_before_result_release_and_revalidated() {
        let (request, session, old, mode) = fixture();
        let committed = Rc::new(Cell::new(false));
        let mut store = Store {
            old: old.clone(),
            intent: None,
            updated: None,
            committed: committed.clone(),
            fail_commit: false,
        };
        let mut machine = SessionResize::new(
            "amaterasu.session-lifecycle",
            request,
            session,
            old,
            mode,
            77,
            0,
            |_, _, _, _| true,
        )
        .unwrap();
        let mut pending: BTreeMap<u64, Value> = BTreeMap::new();
        let mut next = 0;
        let mut native = 0;
        let mut actions = BTreeMap::new();
        let new_borrow = json!({"ok":true,"borrow_id":"c".repeat(64),"observed_output":{"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1280,"height":720,"refresh_millihz":60000},"mutation_domain":{"id":"provider_session:abcdef","revision":5,"borrowers":1,"pending_mutations":0,"scope":"provider_session"}});
        let mut send = |command| match command {
            Command::Request {
                payload,
                operation_id,
                parent,
                ..
            } => {
                assert_eq!(parent, Some(77));
                next += 1;
                let action = payload["action"].as_str().unwrap();
                let mut response = new_borrow.clone();
                if action == "reconfigure" {
                    native += 1;
                    response["operation_id"] = payload["operation_id"].clone();
                    if native == 1 {
                        response = json!({"ok":true,"state":"pending","operation_id":payload["operation_id"]});
                    } else {
                        response["state"] = json!("succeeded");
                    }
                } else {
                    assert_eq!(action, "validate_borrow");
                }
                actions.insert(next, (action.to_owned(), native, operation_id));
                pending.insert(next, response);
                Ok(Response::Accepted { id: next })
            }
            Command::TakeResult { request } => Ok(Response::Result {
                payload: pending[&request].clone(),
            }),
            Command::ReleaseResult { request } => {
                if actions[&request].0 == "reconfigure" && actions[&request].1 == 2 {
                    assert!(
                        committed.get(),
                        "new borrow must be durable before result release"
                    );
                }
                Ok(Response::Ok)
            }
            _ => panic!("unexpected broker command"),
        };
        let mut guard = Guard(true);
        for now in 1..100 {
            if let ResizeProgress::Complete(updated) =
                machine.poll(now, &mut send, &mut store, &mut guard)
            {
                assert_eq!(
                    (updated.width, updated.height, updated.geometry_revision),
                    (1280, 720, 5)
                );
                assert_eq!(native, 2);
                return;
            }
        }
        panic!("resize did not complete")
    }
    #[test]
    fn missing_retirement_and_failed_commit_never_publish() {
        let (request, session, old, mode) = fixture();
        let mut altered = request.clone();
        altered.approved_plan.as_mut().unwrap().constraints["virtual_reconfigure"]["desired"]["width"] =
            json!(640);
        assert!(
            SessionResize::new(
                "amaterasu.session-lifecycle",
                altered,
                session.clone(),
                old.clone(),
                mode.clone(),
                77,
                0,
                |_, _, _, _| true
            )
            .is_err()
        );
        assert!(
            SessionResize::new(
                "amaterasu.session-lifecycle",
                request.clone(),
                session.clone(),
                old.clone(),
                mode.clone(),
                77,
                0,
                |_, _, _, _| false
            )
            .is_err()
        );
        let committed = Rc::new(Cell::new(false));
        let mut store = Store {
            old: old.clone(),
            intent: None,
            updated: None,
            committed,
            fail_commit: true,
        };
        let mut machine = SessionResize::new(
            "amaterasu.session-lifecycle",
            request,
            session,
            old,
            mode,
            77,
            0,
            |_, _, _, _| true,
        )
        .unwrap();
        let mut guard = Guard(false);
        let mut send = |_| panic!("no native effect allowed");
        assert_eq!(
            machine.poll(1, &mut send, &mut store, &mut guard),
            ResizeProgress::Waiting
        );
        assert_eq!(
            machine.poll(2, &mut send, &mut store, &mut guard),
            ResizeProgress::RecoveryRequired
        );
    }
    #[test]
    fn failed_session_commit_keeps_native_result_unreleased_and_unknown() {
        let (request, session, old, mode) = fixture();
        let mut store = Store {
            old: old.clone(),
            intent: None,
            updated: None,
            committed: Rc::new(Cell::new(false)),
            fail_commit: true,
        };
        let mut machine = SessionResize::new(
            "amaterasu.session-lifecycle",
            request,
            session,
            old,
            mode,
            77,
            0,
            |_, _, _, _| true,
        )
        .unwrap();
        let mut payload = Value::Null;
        let mut releases = 0;
        let mut send = |command| match command {
            Command::Request {
                payload: request, ..
            } => {
                payload = json!({"ok":true,"state":"succeeded","operation_id":request["operation_id"],"borrow_id":"c".repeat(64),"observed_output":{"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1280,"height":720,"refresh_millihz":60000},"mutation_domain":{"id":"provider_session:abcdef","revision":5,"borrowers":1,"pending_mutations":0,"scope":"provider_session"}});
                Ok(Response::Accepted { id: 1 })
            }
            Command::TakeResult { .. } => Ok(Response::Result {
                payload: payload.clone(),
            }),
            Command::ReleaseResult { .. } => {
                releases += 1;
                Ok(Response::Ok)
            }
            _ => panic!("unexpected broker call"),
        };
        let mut guard = Guard(true);
        for tick in 1..50 {
            if machine.poll(tick, &mut send, &mut store, &mut guard)
                == ResizeProgress::RecoveryRequired
            {
                assert_eq!(releases, 0);
                assert!(store.updated.is_none());
                return;
            }
        }
        panic!("failed commit did not settle");
    }
    #[test]
    fn changed_compositor_or_domain_cannot_become_session_binding() {
        let (request, session, old, mode) = fixture();
        let machine = SessionResize::new(
            "amaterasu.session-lifecycle",
            request,
            session,
            old.clone(),
            mode,
            77,
            0,
            |_, _, _, _| true,
        )
        .unwrap();
        let mut replacement = old.borrow.unwrap();
        replacement.borrow_id = "c".repeat(64);
        replacement.observed_output.width = 1280;
        replacement.observed_output.height = 720;
        replacement.mutation_domain.revision = 5;
        assert!(machine.new_obligation(replacement.clone()).is_some());
        replacement.observed_output.compositor_id = "d".repeat(64);
        assert!(machine.new_obligation(replacement.clone()).is_none());
        replacement.observed_output.compositor_id = "b".repeat(64);
        replacement.observed_output.registry_global = 8;
        assert!(machine.new_obligation(replacement.clone()).is_none());
        replacement.observed_output.registry_global = 4;
        replacement.mutation_domain.borrowers = 2;
        assert!(machine.new_obligation(replacement.clone()).is_none());
        replacement.mutation_domain.borrowers = 1;
        replacement.mutation_domain.pending_mutations = 1;
        assert!(machine.new_obligation(replacement).is_none());
    }
    #[test]
    fn lost_retirement_before_publication_never_finishes_receipt() {
        let (request, session, old, mode) = fixture();
        let mut machine = SessionResize::new(
            "amaterasu.session-lifecycle",
            request,
            session,
            old.clone(),
            mode,
            77,
            0,
            |_, _, _, _| true,
        )
        .unwrap();
        machine.phase = Phase::GuardFinish;
        machine.updated = Some(old.clone());
        let mut store = Store {
            old,
            intent: None,
            updated: None,
            committed: Rc::new(Cell::new(false)),
            fail_commit: false,
        };
        let mut guard = Guard(false);
        assert_eq!(
            machine.poll(
                1,
                &mut |_| panic!("no effects after retirement is lost"),
                &mut store,
                &mut guard
            ),
            ResizeProgress::RecoveryRequired
        );
        assert!(store.intent.is_none());
    }
    #[test]
    fn expired_admission_after_receipt_write_never_publishes() {
        let (request, session, old, mode) = fixture();
        let mut machine = SessionResize::new(
            "amaterasu.session-lifecycle",
            request,
            session,
            old.clone(),
            mode,
            77,
            0,
            |_, _, _, _| true,
        )
        .unwrap();
        machine.phase = Phase::GuardPublish;
        machine.updated = Some(old.clone());
        let mut store = Store {
            old,
            intent: None,
            updated: None,
            committed: Rc::new(Cell::new(false)),
            fail_commit: false,
        };
        let mut guard = Guard(false);
        assert_eq!(
            machine.poll(
                1,
                &mut |_| panic!("unexpected effect"),
                &mut store,
                &mut guard
            ),
            ResizeProgress::RecoveryRequired
        );
    }
}
