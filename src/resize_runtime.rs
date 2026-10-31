//! Coordinator authorization for resize effects and recovery status.
use crate::coordinator::{PendingVerification, Verification};
use amaterasu_module_sdk::{
    Command, ModuleResult, Response,
    extension_api::{LifecycleTarget, ProviderRequest},
};
const LIFECYCLE_CALLER: &str = "amaterasu.session-lifecycle";

#[derive(Default)]
pub(crate) struct LiveResizeGuard {
    verification: Option<PendingVerification>,
}
impl crate::session_resize::ResizeGuard for LiveResizeGuard {
    fn poll(
        &mut self,
        intent: &crate::session_resize::ResizeIntent,
        parent: u64,
        now: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> crate::virtual_callback::GuardProgress {
        use crate::virtual_callback::GuardProgress;
        if self.verification.is_none() {
            let Ok(v) = PendingVerification::from_request(LIFECYCLE_CALLER, &intent.request, now)
            else {
                return GuardProgress::Unknown;
            };
            self.verification = Some(v);
        }
        let verification = self.verification.as_mut().expect("initialized");
        match verification.poll(now, send) {
            Verification::Pending => GuardProgress::Waiting,
            Verification::Verified
                if verification.consumers_retired() == Some(true)
                    && verification.session_target() == Some(&intent.session_target) =>
            {
                self.verification = None;
                if matches!(
                    send(Command::CheckRequest { request: parent }),
                    Ok(Response::Ok)
                ) {
                    GuardProgress::Authorized
                } else {
                    GuardProgress::Unknown
                }
            }
            Verification::Rejected | Verification::Verified => {
                self.verification = None;
                GuardProgress::Rejected
            }
            Verification::Unknown => {
                self.verification = None;
                GuardProgress::Unknown
            }
        }
    }
}
pub(crate) struct LiveRecoveryGuard {
    request: ProviderRequest,
    verification: Option<PendingVerification>,
}
impl LiveRecoveryGuard {
    pub(crate) fn new(request: ProviderRequest) -> Self {
        Self {
            request,
            verification: None,
        }
    }
}
impl crate::resize_recovery::RecoveryGuard for LiveRecoveryGuard {
    fn poll(
        &mut self,
        intent: &crate::session_resize::ResizeIntent,
        session: &LifecycleTarget,
        now: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> crate::virtual_callback::GuardProgress {
        use crate::virtual_callback::GuardProgress;
        if intent.request != self.request || &intent.session_target != session {
            return GuardProgress::Rejected;
        }
        if self.verification.is_none() {
            let Ok(v) = PendingVerification::from_request(LIFECYCLE_CALLER, &self.request, now)
            else {
                return GuardProgress::Unknown;
            };
            self.verification = Some(v);
        }
        let v = self.verification.as_mut().expect("initialized");
        match v.poll(now, send) {
            Verification::Pending => GuardProgress::Waiting,
            Verification::Verified
                if v.consumers_retired() == Some(true) && v.session_target() == Some(session) =>
            {
                self.verification = None;
                GuardProgress::Authorized
            }
            Verification::Rejected | Verification::Verified => {
                self.verification = None;
                GuardProgress::Rejected
            }
            Verification::Unknown => {
                self.verification = None;
                GuardProgress::Unknown
            }
        }
    }
}
