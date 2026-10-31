//! Persist independently observed action borrowers with exact prior CAS.
use crate::observation_refresh::JournalObservation;
use amaterasu_module_sdk::{Command, ModuleResult, Response};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub enum ObservationWriteProgress {
    Waiting,
    Complete,
    Unknown,
}
pub struct ObservationWriter {
    journals: Vec<JournalObservation>,
    index: usize,
    phase: u8,
    id: Option<u64>,
    result: Option<Value>,
    command: Command,
    nonce: String,
    parent: u64,
    deadline: u64,
    expected: Option<u64>,
    failures: u8,
}
impl ObservationWriter {
    pub fn new(
        journals: Vec<JournalObservation>,
        parent: u64,
        now: u64,
        timeout: u64,
    ) -> Result<Self, &'static str> {
        if journals.is_empty()
            || journals.len() > 128
            || parent == 0
            || timeout == 0
            || journals.iter().any(|journal| !valid_delta(journal))
        {
            return Err("invalid_observations");
        }
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| "random_unavailable")?;
        let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut writer = Self {
            journals,
            index: 0,
            phase: 0,
            id: None,
            result: None,
            command: Command::CheckRequest { request: parent },
            nonce,
            parent,
            deadline: now.saturating_add(timeout.min(30_000)),
            expected: None,
            failures: 0,
        };
        writer.issue_get(now)?;
        Ok(writer)
    }
    fn key(&self) -> Result<String, &'static str> {
        let target = &self.journals[self.index].target;
        let bytes = serde_json::to_vec(target).map_err(|_| "invalid_target")?;
        Ok(format!(
            "virtual-obligation/v1/target-{:x}",
            Sha256::digest(bytes)
        ))
    }
    fn command(&self, payload: Value, label: &str, now: u64) -> Command {
        Command::Request {
            service: "amaterasu.state/1".into(),
            payload,
            timeout_ms: self.deadline.saturating_sub(now).min(30_000),
            operation_id: format!("action-refresh.{}.{}.{}", self.nonce, self.index, label),
            parent: Some(self.parent),
        }
    }
    fn issue_get(&mut self, now: u64) -> Result<(), &'static str> {
        self.command = self.command(json!({"action":"get","key":self.key()?}), "read", now);
        self.id = None;
        self.result = None;
        self.phase = 0;
        Ok(())
    }
    pub fn poll(
        &mut self,
        now: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> ObservationWriteProgress {
        if now >= self.deadline || self.failures >= 3 {
            return ObservationWriteProgress::Unknown;
        }
        if let Some(id) = self.id {
            if let Some(value) = self.result.take() {
                if !matches!(
                    send(Command::ReleaseResult { request: id }),
                    Ok(Response::Ok)
                ) {
                    self.result = Some(value);
                    self.failures += 1;
                    return ObservationWriteProgress::Waiting;
                }
                self.id = None;
                if self.phase == 0 {
                    if value["ok"] != true || value["found"] != true {
                        return ObservationWriteProgress::Unknown;
                    }
                    let Ok(current) = serde_json::from_value::<
                        crate::virtual_callback::VirtualObligation,
                    >(value["value"].clone()) else {
                        return ObservationWriteProgress::Unknown;
                    };
                    if current != self.journals[self.index].before {
                        return ObservationWriteProgress::Unknown;
                    }
                    let Some(revision) = value["revision"].as_u64() else {
                        return ObservationWriteProgress::Unknown;
                    };
                    let Some(next) = revision.checked_add(1) else {
                        return ObservationWriteProgress::Unknown;
                    };
                    let payload = json!(self.journals[self.index].observed);
                    self.expected = Some(next);
                    let Ok(key) = self.key() else {
                        return ObservationWriteProgress::Unknown;
                    };
                    self.command=self.command(json!({"action":"set","key":key,"value":payload,"expected_revision":revision}),"write",now);
                    self.phase = 1;
                    self.failures = 0;
                    return ObservationWriteProgress::Waiting;
                }
                if value["ok"] != true || value["revision"].as_u64() != self.expected {
                    return ObservationWriteProgress::Unknown;
                }
                self.index += 1;
                if self.index == self.journals.len() {
                    return ObservationWriteProgress::Complete;
                }
                if self.issue_get(now).is_err() {
                    return ObservationWriteProgress::Unknown;
                }
                self.failures = 0;
                return ObservationWriteProgress::Waiting;
            }
            match send(Command::TakeResult { request: id }) {
                Ok(Response::Pending) => ObservationWriteProgress::Waiting,
                Ok(Response::Result { payload }) => {
                    self.result = Some(payload);
                    ObservationWriteProgress::Waiting
                }
                _ => {
                    self.failures += 1;
                    ObservationWriteProgress::Waiting
                }
            }
        } else {
            match send(self.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.id = Some(id);
                    self.failures = 0;
                    ObservationWriteProgress::Waiting
                }
                _ => {
                    self.failures += 1;
                    ObservationWriteProgress::Waiting
                }
            }
        }
    }
}
fn valid_delta(journal: &JournalObservation) -> bool {
    let (Some(old), Some(new)) = (&journal.before.borrow, &journal.observed.borrow) else {
        return false;
    };
    let mut prior = journal.before.clone();
    let mut updated = journal.observed.clone();
    prior.borrow = None;
    updated.borrow = None;
    prior == updated
        && old.borrow_id == new.borrow_id
        && old.observed_output == new.observed_output
        && old.mutation_domain.id == new.mutation_domain.id
        && old.mutation_domain.scope == new.mutation_domain.scope
        && new.mutation_domain.revision >= old.mutation_domain.revision
        && new.mutation_domain.pending_mutations == 0
        && new.mutation_domain.borrowers > 0
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_callback::VirtualObligation;
    fn journal() -> JournalObservation {
        let before:VirtualObligation=serde_json::from_value(json!({"provider_service":"amaterasu.virtual-display/1","identity":"11111111-1111-4111-8111-111111111111","reference_id":"ref-1","width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false,"scale":null,"layout":"extended","domain_id":"provider_session:abc","domain_revision":1,"geometry_revision":1,"borrow":{"borrow_id":"a".repeat(64),"observed_output":{"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1920,"height":1080,"refresh_millihz":60000},"mutation_domain":{"id":"provider_session:abc","revision":2,"borrowers":1,"pending_mutations":0,"scope":"provider_session"}},"reference_released":false})).unwrap();
        let mut observed = before.clone();
        observed.borrow.as_mut().unwrap().mutation_domain.revision = 3;
        JournalObservation{target:serde_json::from_value(json!({"kind":"session","host_epoch":"epoch","session_id":"session","generation":1})).unwrap(),before,observed}
    }
    #[test]
    fn observation_cas_rejects_stale_prior() {
        for stale in [false, true] {
            let observation = journal();
            let mut writer =
                ObservationWriter::new(vec![observation.clone()], 77, 0, 1000).unwrap();
            let mut value = json!(observation.before);
            if stale {
                value["geometry_revision"] = json!(9)
            }
            let mut pending = Value::Null;
            let mut writes = 0;
            let mut send = |command| match command {
                Command::Request { payload, .. } => {
                    pending = if payload["action"] == "get" {
                        json!({"ok":true,"found":true,"value":value,"revision":2})
                    } else {
                        writes += 1;
                        assert_eq!(payload["expected_revision"], 2);
                        value = payload["value"].clone();
                        json!({"ok":true,"revision":3})
                    };
                    Ok(Response::Accepted { id: 1 })
                }
                Command::TakeResult { .. } => Ok(Response::Result {
                    payload: pending.clone(),
                }),
                Command::ReleaseResult { .. } => Ok(Response::Ok),
                _ => panic!("unexpected"),
            };
            let mut completed = false;
            for tick in 1..30 {
                match writer.poll(tick, &mut send) {
                    ObservationWriteProgress::Waiting => {}
                    ObservationWriteProgress::Complete => {
                        completed = true;
                        break;
                    }
                    ObservationWriteProgress::Unknown => break,
                }
            }
            assert_eq!(completed, !stale);
            assert_eq!(writes, usize::from(!stale));
            if !stale {
                assert_eq!(value["borrow"]["mutation_domain"]["revision"], 3);
            }
        }
    }
}
