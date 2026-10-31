//! Atomic session resize intent and ownership lineage in the state service.
use crate::{
    session_resize::{ResizeIntent, ResizeStore, ResizeStoreCommand, ResizeStoreProgress},
    virtual_callback::VirtualObligation,
};
use amaterasu_module_sdk::{
    Command, ModuleResult, Response,
    extension_api::{LifecyclePhase, LifecycleTarget, ProviderOperation},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_LINEAGE: usize = 8;
const MAX_ENVELOPE_BYTES: usize = 15_000;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResizeRecordState {
    Pending,
    Committed,
    Completed,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResizeRecord {
    pub intent: ResizeIntent,
    pub updated: Option<VirtualObligation>,
    pub state: ResizeRecordState,
}
/// Compact checkpoint written only after a fully validated, guarded resize.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SettledResize {
    pub session_target: LifecycleTarget,
    pub prior: VirtualObligation,
    pub updated: VirtualObligation,
    pub provider_sequence: u64,
    pub provider_operation_id: String,
    pub request_digest: String,
    pub native_operation_id: String,
}
impl SettledResize {
    fn from_record(record: ResizeRecord) -> Result<Self, &'static str> {
        if record.state != ResizeRecordState::Completed {
            return Err("invalid_settled_resize");
        }
        let updated = record.updated.ok_or("invalid_settled_resize")?;
        if !valid_update(&record.intent, &updated) {
            return Err("invalid_settled_resize");
        }
        let digest = request_digest(&record.intent.request)?;
        Ok(Self {
            session_target: record.intent.session_target,
            prior: record.intent.prior,
            updated,
            provider_sequence: record.intent.request.provider_sequence,
            provider_operation_id: record.intent.request.operation_id,
            request_digest: digest,
            native_operation_id: record.intent.operation_id,
        })
    }
}
impl<'de> Deserialize<'de> for SettledResize {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Compact {
            session_target: LifecycleTarget,
            prior: VirtualObligation,
            updated: VirtualObligation,
            provider_sequence: u64,
            provider_operation_id: String,
            request_digest: String,
            native_operation_id: String,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Compact(Box<Compact>),
            Legacy(Box<ResizeRecord>),
        }
        match Wire::deserialize(deserializer)? {
            Wire::Compact(c) => Ok(Self {
                session_target: c.session_target,
                prior: c.prior,
                updated: c.updated,
                provider_sequence: c.provider_sequence,
                provider_operation_id: c.provider_operation_id,
                request_digest: c.request_digest,
                native_operation_id: c.native_operation_id,
            }),
            Wire::Legacy(r) => Self::from_record(*r).map_err(serde::de::Error::custom),
        }
    }
}
pub(crate) fn request_digest(
    request: &amaterasu_module_sdk::extension_api::ProviderRequest,
) -> Result<String, &'static str> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(request).map_err(|_| "invalid_request")?)
    ))
}
fn valid_settled(r: &SettledResize) -> bool {
    matches!(&r.session_target, LifecycleTarget::Session { host_epoch, session_id, generation } if !host_epoch.is_empty() && host_epoch.len()<=128 && host_epoch.bytes().all(|b|b.is_ascii_graphic()) && !session_id.is_empty() && session_id.len()<=128 && session_id.bytes().all(|b|b.is_ascii_graphic()) && *generation>0)
        && r.provider_sequence > 0
        && !r.provider_operation_id.is_empty()
        && r.provider_operation_id.len() <= 128
        && r.provider_operation_id
            .bytes()
            .all(|b| b.is_ascii_graphic())
        && !r.native_operation_id.is_empty()
        && r.native_operation_id.len() <= 128
        && r.native_operation_id.bytes().all(|b| b.is_ascii_graphic())
        && r.request_digest.len() == 64
        && r.request_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && valid_compact_transition(&r.prior, &r.updated)
}
fn valid_compact_transition(prior: &VirtualObligation, updated: &VirtualObligation) -> bool {
    let (Some(old), Some(new)) = (&prior.borrow, &updated.borrow) else {
        return false;
    };
    let reference = crate::virtual_display::DisplayReference {
        identity: prior.identity.clone(),
        reference_id: prior.reference_id.clone(),
    };
    let mut expected = prior.clone();
    expected.width = updated.width;
    expected.height = updated.height;
    expected.refresh_millihz = updated.refresh_millihz;
    expected.geometry_revision = new.mutation_domain.revision;
    expected.borrow = Some(new.clone());
    reference.validate().is_ok()
        && prior.provider_service == crate::virtual_display::SERVICE
        && !prior.reference_released
        && prior.geometry_revision != 0
        && (320..=7680).contains(&prior.width)
        && (200..=4320).contains(&prior.height)
        && (1000..=1_000_000).contains(&prior.refresh_millihz)
        && (320..=7680).contains(&updated.width)
        && (200..=4320).contains(&updated.height)
        && (1000..=1_000_000).contains(&updated.refresh_millihz)
        && prior.name.len() <= 31
        && !prior.name.is_empty()
        && prior
            .name
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
        && matches!(prior.layout.as_str(), "extended" | "exclusive")
        && prior.scale.is_none_or(|n| n == 0)
        && old.borrow_id.len() == 64
        && old
            .borrow_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && new.borrow_id.len() == 64
        && new
            .borrow_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && new.borrow_id != old.borrow_id
        && old.mutation_domain.id == prior.domain_id
        && old.mutation_domain.scope == "provider_session"
        && old.mutation_domain.borrowers == 1
        && old.mutation_domain.pending_mutations == 0
        && old.observed_output.width == prior.width
        && old.observed_output.height == prior.height
        && old.observed_output.refresh_millihz == prior.refresh_millihz
        && new.mutation_domain.id == old.mutation_domain.id
        && new.mutation_domain.scope == "provider_session"
        && new.mutation_domain.borrowers == 1
        && new.mutation_domain.pending_mutations == 0
        && new.mutation_domain.revision > old.mutation_domain.revision
        && new.observed_output.width == updated.width
        && new.observed_output.height == updated.height
        && new.observed_output.refresh_millihz == updated.refresh_millihz
        && *updated == expected
        && same_producer(prior, updated)
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResizeEnvelope {
    pub format_version: u8,
    pub obligation: VirtualObligation,
    pub active: Option<ResizeRecord>,
    #[serde(default)]
    pub checkpoint: Option<SettledResize>,
    pub lineage: Vec<SettledResize>,
}
/// Decode an exact legacy obligation or the versioned envelope. No malformed
/// envelope is downgraded to legacy. Active resize must fence normal readers.
pub fn decode_envelope(value: Value) -> Result<ResizeEnvelope, &'static str> {
    let envelope = if value.get("format_version").is_some() {
        serde_json::from_value::<ResizeEnvelope>(value).map_err(|_| "invalid_resize_envelope")?
    } else {
        ResizeEnvelope {
            format_version: 1,
            obligation: serde_json::from_value(value).map_err(|_| "invalid_resize_envelope")?,
            active: None,
            checkpoint: None,
            lineage: vec![],
        }
    };
    if envelope.format_version != 1
        || envelope.lineage.len() > MAX_LINEAGE
        || envelope.checkpoint.as_ref().is_some_and(|root| {
            !valid_settled(root)
                || envelope.lineage.first().is_none_or(|latest| {
                    root.session_target != latest.session_target
                        || root.provider_sequence >= latest.provider_sequence
                        || !same_producer(&root.updated, &latest.updated)
                })
        })
        || envelope.lineage.iter().any(|r| !valid_settled(r))
        || envelope.lineage.windows(2).any(|w| {
            w[0].provider_sequence >= w[1].provider_sequence
                || w[0].session_target != w[1].session_target
                || !same_owned_after_observation(&w[0].updated, &w[1].prior)
        })
        || envelope.active.as_ref().is_some_and(|r| match r.state {
            ResizeRecordState::Pending => {
                !valid_intent(&r.intent)
                    || r.updated.is_some()
                    || r.intent.prior != envelope.obligation
            }
            ResizeRecordState::Committed => {
                r.updated.as_ref() != Some(&envelope.obligation)
                    || r.updated
                        .as_ref()
                        .is_none_or(|u| !valid_update(&r.intent, u))
            }
            ResizeRecordState::Completed => true,
        })
        || envelope.active.as_ref().is_some_and(|r| {
            envelope.lineage.last().is_some_and(|last| {
                last.provider_sequence >= r.intent.request.provider_sequence
                    || last.session_target != r.intent.session_target
                    || !same_owned_after_observation(&last.updated, &r.intent.prior)
            })
        })
        || serde_json::to_vec(&envelope).map_or(true, |v| v.len() > MAX_ENVELOPE_BYTES)
    {
        return Err("invalid_resize_envelope");
    }
    Ok(envelope)
}
/// Store callers must authenticate the exact coordinator-selected request and
/// session journal before constructing this adapter.
pub struct DurableResizeStore {
    intent: ResizeIntent,
    key: String,
    prefix: String,
    parent: Option<u64>,
    timeout: u64,
    now: u64,
    serial: u64,
    active: Option<Pending>,
    ready: Option<(ResizeStoreCommand, ResizeStoreProgress)>,
    poisoned: bool,
}
struct Pending {
    command: ResizeStoreCommand,
    phase: u8,
    broker: Command,
    id: Option<u64>,
    result: Option<Value>,
    attempts: u8,
    deadline: u64,
    expected_revision: Option<u64>,
    prefix: String,
}
impl DurableResizeStore {
    pub fn new(
        caller: &str,
        intent: ResizeIntent,
        prefix: String,
        parent: Option<u64>,
        timeout: u64,
        verify: impl FnOnce(&ResizeIntent) -> bool,
    ) -> Result<Self, &'static str> {
        if caller != "amaterasu.session-lifecycle"
            || !valid_intent(&intent)
            || !verify(&intent)
            || prefix.is_empty()
            || prefix.len() > 64
            || !prefix.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
            || !(1..=30_000).contains(&timeout)
        {
            return Err("invalid_resize_authority");
        }
        let bytes = serde_json::to_vec(&intent.session_target).map_err(|_| "invalid_target")?;
        let key = format!("virtual-obligation/v1/target-{:x}", Sha256::digest(bytes));
        Ok(Self {
            intent,
            key,
            prefix,
            parent,
            timeout,
            now: 0,
            serial: 0,
            active: None,
            ready: None,
            poisoned: false,
        })
    }
    pub fn advance(&mut self, now: u64, send: &mut impl FnMut(Command) -> ModuleResult<Response>) {
        if now < self.now {
            self.poisoned = true;
            return;
        }
        self.now = now;
        let Some(mut pending) = self.active.take() else {
            return;
        };
        match pending.poll(now, &self.key, self.parent, self.timeout, send) {
            None => self.active = Some(pending),
            Some(result) => self.ready = Some((pending.command, result)),
        }
    }
}
impl ResizeStore for DurableResizeStore {
    fn poll(&mut self, command: &ResizeStoreCommand) -> ResizeStoreProgress {
        if self.poisoned {
            return ResizeStoreProgress::Unknown;
        }
        if let Some((previous, result)) = self.ready.take() {
            if previous != *command {
                self.poisoned = true;
                return ResizeStoreProgress::Unknown;
            }
            if result == ResizeStoreProgress::Unknown {
                self.poisoned = true;
            }
            return result;
        }
        if let Some(active) = &self.active {
            if active.command != *command {
                self.poisoned = true;
                return ResizeStoreProgress::Unknown;
            }
            return ResizeStoreProgress::Waiting;
        }
        let intent = match command {
            ResizeStoreCommand::Begin { intent }
            | ResizeStoreCommand::Commit { intent, .. }
            | ResizeStoreCommand::Finish { intent, .. } => intent,
        };
        if *intent != self.intent {
            self.poisoned = true;
            return ResizeStoreProgress::Unknown;
        }
        let Some(serial) = self.serial.checked_add(1) else {
            self.poisoned = true;
            return ResizeStoreProgress::Unknown;
        };
        self.serial = serial;
        let prefix = format!("{}.{}", self.prefix, serial);
        let broker = broker(
            json!({"action":"get","key":self.key}),
            &prefix,
            "read",
            0,
            self.parent,
            self.timeout,
        );
        self.active = Some(Pending {
            command: command.clone(),
            phase: 0,
            broker,
            id: None,
            result: None,
            attempts: 0,
            deadline: self.now.saturating_add(self.timeout),
            expected_revision: None,
            prefix,
        });
        ResizeStoreProgress::Waiting
    }
}
impl Pending {
    fn poll(
        &mut self,
        now: u64,
        key: &str,
        parent: Option<u64>,
        timeout: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> Option<ResizeStoreProgress> {
        if now >= self.deadline || self.attempts >= 3 {
            return Some(ResizeStoreProgress::Unknown);
        }
        if let Some(id) = self.id {
            if self.result.is_none() {
                match send(Command::TakeResult { request: id }) {
                    Ok(Response::Pending) => {}
                    Ok(Response::Result { payload }) => self.result = Some(payload),
                    _ => return Some(ResizeStoreProgress::Unknown),
                }
                return None;
            }
            if !matches!(
                send(Command::ReleaseResult { request: id }),
                Ok(Response::Ok)
            ) {
                return Some(ResizeStoreProgress::Unknown);
            }
            let result = self.result.take()?;
            if result["ok"] != true {
                if self.phase == 1
                    && result.pointer("/error/code") == Some(&json!("revision_conflict"))
                {
                    self.attempts += 1;
                    self.phase = 0;
                    self.broker = broker(
                        json!({"action":"get","key":key}),
                        &self.prefix,
                        "read",
                        self.attempts,
                        parent,
                        timeout,
                    );
                    self.id = None;
                    return None;
                }
                return Some(ResizeStoreProgress::Unknown);
            }
            if self.phase == 1 {
                return Some(if result["revision"].as_u64() == self.expected_revision {
                    ResizeStoreProgress::Applied
                } else {
                    ResizeStoreProgress::Unknown
                });
            }
            if result["found"] != true {
                return Some(ResizeStoreProgress::Unknown);
            }
            let Some(revision) = result["revision"].as_u64() else {
                return Some(ResizeStoreProgress::Unknown);
            };
            let Ok(mut envelope) = decode_envelope(result["value"].clone()) else {
                return Some(ResizeStoreProgress::Unknown);
            };
            match decide(&self.command, &mut envelope) {
                Decision::Done(value) => Some(value),
                Decision::Write => {
                    let Ok(value) = serde_json::to_value(envelope) else {
                        return Some(ResizeStoreProgress::Unknown);
                    };
                    if serde_json::to_vec(&value).map_or(true, |v| v.len() > MAX_ENVELOPE_BYTES) {
                        return Some(ResizeStoreProgress::Unknown);
                    }
                    self.expected_revision = revision.checked_add(1);
                    if self.expected_revision.is_none() {
                        return Some(ResizeStoreProgress::Unknown);
                    }
                    self.phase = 1;
                    self.broker = broker(
                        json!({"action":"set","key":key,"expected_revision":revision,"value":value}),
                        &self.prefix,
                        "write",
                        self.attempts,
                        parent,
                        timeout,
                    );
                    self.id = None;
                    None
                }
            }
        } else {
            match send(self.broker.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.id = Some(id);
                    None
                }
                _ => Some(ResizeStoreProgress::Unknown),
            }
        }
    }
}
enum Decision {
    Done(ResizeStoreProgress),
    Write,
}
fn decide(command: &ResizeStoreCommand, envelope: &mut ResizeEnvelope) -> Decision {
    match command {
        ResizeStoreCommand::Begin { intent } => {
            if envelope.active.is_some()
                || envelope
                    .lineage
                    .last()
                    .is_some_and(|r| r.provider_sequence >= intent.request.provider_sequence)
            {
                return Decision::Done(ResizeStoreProgress::ExistingPending);
            }
            if envelope.obligation != intent.prior
                || envelope
                    .lineage
                    .last()
                    .is_some_and(|last| !same_owned_after_observation(&last.updated, &intent.prior))
            {
                return Decision::Done(ResizeStoreProgress::Unknown);
            }
            envelope.active = Some(ResizeRecord {
                intent: intent.clone(),
                updated: None,
                state: ResizeRecordState::Pending,
            });
            Decision::Write
        }
        ResizeStoreCommand::Commit { intent, updated } => {
            let Some(active) = envelope.active.as_mut() else {
                return Decision::Done(ResizeStoreProgress::Unknown);
            };
            if active.intent != *intent || !valid_update(intent, updated) {
                return Decision::Done(ResizeStoreProgress::Unknown);
            }
            match active.state {
                ResizeRecordState::Pending if envelope.obligation == intent.prior => {
                    active.updated = Some(updated.clone());
                    active.state = ResizeRecordState::Committed;
                    envelope.obligation = updated.clone();
                    Decision::Write
                }
                ResizeRecordState::Committed
                    if active.updated.as_ref() == Some(updated)
                        && envelope.obligation == *updated =>
                {
                    Decision::Done(ResizeStoreProgress::Applied)
                }
                _ => Decision::Done(ResizeStoreProgress::Unknown),
            }
        }
        ResizeStoreCommand::Finish { intent, updated } => {
            if envelope.active.is_none()
                && envelope.lineage.last().is_some_and(|r| {
                    r.provider_operation_id == intent.request.operation_id
                        && request_digest(&intent.request).ok().as_deref()
                            == Some(&r.request_digest)
                        && r.native_operation_id == intent.operation_id
                        && r.updated == *updated
                })
            {
                return Decision::Done(ResizeStoreProgress::Applied);
            }
            let Some(mut active) = envelope.active.take() else {
                return Decision::Done(ResizeStoreProgress::Unknown);
            };
            if active.intent != *intent
                || active.state != ResizeRecordState::Committed
                || active.updated.as_ref() != Some(updated)
                || envelope.obligation != *updated
                || !valid_update(intent, updated)
            {
                return Decision::Done(ResizeStoreProgress::Unknown);
            }
            active.state = ResizeRecordState::Completed;
            let Ok(settled) = SettledResize::from_record(active) else {
                return Decision::Done(ResizeStoreProgress::Unknown);
            };
            if envelope.checkpoint.is_none() && !envelope.lineage.is_empty() {
                envelope.checkpoint = envelope.lineage.first().cloned();
            }
            if envelope.checkpoint.is_some() {
                envelope.lineage.clear();
            }
            envelope.lineage.push(settled);
            Decision::Write
        }
    }
}
fn same_producer(a: &VirtualObligation, b: &VirtualObligation) -> bool {
    let (Some(x), Some(y)) = (&a.borrow, &b.borrow) else {
        return false;
    };
    a.identity == b.identity
        && a.reference_id == b.reference_id
        && a.domain_id == b.domain_id
        && crate::virtual_callback::producer_incarnation(
            &a.domain_id,
            &a.identity,
            &x.observed_output,
        ) == crate::virtual_callback::producer_incarnation(
            &b.domain_id,
            &b.identity,
            &y.observed_output,
        )
}
fn same_owned_after_observation(old: &VirtualObligation, current: &VirtualObligation) -> bool {
    let (Some(a), Some(b)) = (&old.borrow, &current.borrow) else {
        return false;
    };
    let mut original = old.clone();
    original.borrow = None;
    let mut next = current.clone();
    next.borrow = None;
    original == next
        && a.borrow_id == b.borrow_id
        && a.observed_output == b.observed_output
        && a.mutation_domain.id == b.mutation_domain.id
        && a.mutation_domain.scope == b.mutation_domain.scope
        && b.mutation_domain.revision >= a.mutation_domain.revision
        && b.mutation_domain.pending_mutations == 0
        && b.mutation_domain.borrowers == 1
}
fn valid_intent(intent: &ResizeIntent) -> bool {
    let Some(borrow) = intent.prior.borrow.as_ref() else {
        return false;
    };
    let reference = crate::virtual_display::DisplayReference {
        identity: intent.prior.identity.clone(),
        reference_id: intent.prior.reference_id.clone(),
    };
    let compatible = matches!((&intent.request.target,&intent.session_target),(LifecycleTarget::Stream{host_epoch:a,session_id:b,..},LifecycleTarget::Session{host_epoch:c,session_id:d,generation}) if a==c && b==d && *generation!=0);
    compatible
        && intent.request.operation == ProviderOperation::LifecycleCallback
        && intent.request.phase == LifecyclePhase::StreamPrepare
        && amaterasu_module_sdk::extension_api::validate_provider_request(&intent.request).is_ok()
        && intent.request.approved_plan.as_ref().is_some_and(|plan| plan.constraints.get("virtual_reconfigure") == Some(&json!({"session_target":intent.session_target,"prior":intent.prior,"desired":intent.desired})))
        && !intent.operation_id.is_empty()
        && intent.operation_id.len() <= 128
        && intent.operation_id.bytes().all(|b| b.is_ascii_graphic())
        && reference.validate().is_ok()
        && intent.prior.provider_service == crate::virtual_display::SERVICE
        && !intent.prior.reference_released
        && intent.desired.hdr == intent.prior.hdr_enabled
        && (320..=7680).contains(&intent.desired.width)
        && (200..=4320).contains(&intent.desired.height)
        && (1000..=1_000_000).contains(&intent.desired.refresh_millihz)
        && intent.prior.geometry_revision != 0
        && borrow.mutation_domain.id == intent.prior.domain_id
        && borrow.mutation_domain.scope == "provider_session"
        && borrow.mutation_domain.borrowers == 1
        && borrow.mutation_domain.pending_mutations == 0
        && borrow.observed_output.width == intent.prior.width
        && borrow.observed_output.height == intent.prior.height
        && borrow.observed_output.refresh_millihz == intent.prior.refresh_millihz
}
pub(crate) fn recovered_obligation(
    intent: &ResizeIntent,
    borrow: crate::virtual_display::DisplayBorrow,
) -> Option<VirtualObligation> {
    let mut updated = intent.prior.clone();
    updated.width = intent.desired.width;
    updated.height = intent.desired.height;
    updated.refresh_millihz = intent.desired.refresh_millihz;
    updated.geometry_revision = borrow.mutation_domain.revision;
    updated.borrow = Some(borrow);
    valid_update(intent, &updated).then_some(updated)
}
pub(crate) fn valid_update(intent: &ResizeIntent, updated: &VirtualObligation) -> bool {
    let Some(old) = intent.prior.borrow.as_ref() else {
        return false;
    };
    let Some(new) = updated.borrow.as_ref() else {
        return false;
    };
    let mut expected = intent.prior.clone();
    expected.width = intent.desired.width;
    expected.height = intent.desired.height;
    expected.refresh_millihz = intent.desired.refresh_millihz;
    if new.mutation_domain.revision == 0 {
        return false;
    }
    expected.geometry_revision = new.mutation_domain.revision;
    expected.borrow = Some(new.clone());
    valid_intent(intent)
        && *updated == expected
        && new.borrow_id.len() == 64
        && new
            .borrow_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && new.borrow_id != old.borrow_id
        && new.mutation_domain.id == old.mutation_domain.id
        && new.mutation_domain.scope == "provider_session"
        && new.mutation_domain.borrowers == 1
        && new.mutation_domain.pending_mutations == 0
        && new.mutation_domain.revision > old.mutation_domain.revision
        && crate::virtual_callback::producer_incarnation(
            &intent.prior.domain_id,
            &intent.prior.identity,
            &old.observed_output,
        ) == crate::virtual_callback::producer_incarnation(
            &updated.domain_id,
            &updated.identity,
            &new.observed_output,
        )
        && new.observed_output.compositor_id == old.observed_output.compositor_id
        && new.observed_output.output_name == old.observed_output.output_name
        && new.observed_output.width == intent.desired.width
        && new.observed_output.height == intent.desired.height
        && new.observed_output.refresh_millihz == intent.desired.refresh_millihz
}
fn broker(
    payload: Value,
    prefix: &str,
    label: &str,
    attempt: u8,
    parent: Option<u64>,
    timeout: u64,
) -> Command {
    Command::Request {
        service: "amaterasu.state/1".into(),
        payload,
        operation_id: format!("{prefix}.{label}.{attempt}"),
        parent,
        timeout_ms: timeout,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    pub(crate) fn fixture() -> (ResizeIntent, VirtualObligation) {
        let plan = json!({"plan_id":"plan-1","revision":1,"resources":[],"mutation_domains":[],"required_capabilities":[],"constraints":{},"obligations":[],"affected_consumers":[],"consumer_change":"reconnect_required","candidate_constraint":null,"allowed_degradation":[]});
        let request=serde_json::from_value(json!({"provider_sequence":2,"operation":"lifecycle_callback","version":1,"transition_id":"transition","operation_id":"op-2","target":{"kind":"stream","host_epoch":"epoch","session_id":"session","stream_id":"stream","generation":2},"phase":"stream.prepare","settings_revision":"settings","settings":{},"intent":"resume","reason":null,"requested_video":{"width":1280,"height":720,"refresh_millihz":60000,"hdr":false},"consumer_requirements":{"execution_domain":"desktop","capture_providers":["capture"],"selector_schemas":["schema"]},"remaining_ms":5000,"plan_revision":1,"admission_id":"admission","approved_plan":plan})).unwrap();
        let session_target = serde_json::from_value(
            json!({"kind":"session","host_epoch":"epoch","session_id":"session","generation":1}),
        )
        .unwrap();
        let prior:VirtualObligation=serde_json::from_value(json!({"provider_service":"amaterasu.virtual-display/1","identity":"11111111-1111-4111-8111-111111111111","reference_id":"ref-1","width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false,"scale":null,"layout":"extended","domain_id":"provider_session:abcdef","domain_revision":1,"geometry_revision":1,"borrow":{"borrow_id":"a".repeat(64),"observed_output":{"version":1,"protocol":"wayland-wl-output","compositor_id":"b".repeat(64),"registry_global":4,"output_name":"Virtual-1","width":1920,"height":1080,"refresh_millihz":60000},"mutation_domain":{"id":"provider_session:abcdef","revision":3,"borrowers":1,"pending_mutations":0,"scope":"provider_session"}},"reference_released":false})).unwrap();
        let desired = serde_json::from_value(
            json!({"width":1280,"height":720,"refresh_millihz":60000,"hdr":false}),
        )
        .unwrap();
        let mut intent = ResizeIntent {
            request,
            session_target,
            prior: prior.clone(),
            desired,
            operation_id: "resize.abc".into(),
        };
        intent.request.approved_plan.as_mut().unwrap().constraints["virtual_reconfigure"] = json!({"session_target":intent.session_target,"prior":intent.prior,"desired":intent.desired});
        let mut updated = prior;
        updated.width = 1280;
        updated.height = 720;
        updated.geometry_revision = 4;
        let borrow = updated.borrow.as_mut().unwrap();
        borrow.borrow_id = "c".repeat(64);
        borrow.observed_output.width = 1280;
        borrow.observed_output.height = 720;
        borrow.mutation_domain.revision = 4;
        (intent, updated)
    }
    #[derive(Default)]
    struct Fake {
        revision: u64,
        values: BTreeMap<String, Value>,
        result: Option<Value>,
        id: u64,
        conflict: bool,
        lost_ack: bool,
    }
    impl Fake {
        fn send(&mut self, c: Command) -> ModuleResult<Response> {
            match c {
                Command::Request { payload, .. } => {
                    let key = payload["key"].as_str().unwrap().to_owned();
                    let result = match payload["action"].as_str().unwrap() {
                        "get" => {
                            json!({"ok":true,"revision":self.revision,"found":self.values.contains_key(&key),"value":self.values.get(&key)})
                        }
                        "set" if self.conflict => {
                            self.conflict = false;
                            json!({"ok":false,"error":{"code":"revision_conflict"}})
                        }
                        "set" if payload["expected_revision"].as_u64() == Some(self.revision) => {
                            self.values.insert(key, payload["value"].clone());
                            self.revision += 1;
                            if self.lost_ack {
                                self.lost_ack = false;
                                return Err("lost acknowledgement".into());
                            }
                            json!({"ok":true,"revision":self.revision})
                        }
                        _ => json!({"ok":false,"error":{"code":"revision_conflict"}}),
                    };
                    self.id += 1;
                    self.result = Some(result);
                    Ok(Response::Accepted { id: self.id })
                }
                Command::TakeResult { .. } => Ok(Response::Result {
                    payload: self.result.clone().unwrap(),
                }),
                Command::ReleaseResult { .. } => Ok(Response::Ok),
                _ => panic!("unexpected"),
            }
        }
        fn run(
            &mut self,
            store: &mut DurableResizeStore,
            command: ResizeStoreCommand,
        ) -> ResizeStoreProgress {
            for _ in 0..50 {
                let p = store.poll(&command);
                if p != ResizeStoreProgress::Waiting {
                    return p;
                }
                store.advance(store.now + 1, &mut |c| self.send(c));
            }
            panic!("stuck")
        }
    }
    fn store(intent: ResizeIntent) -> DurableResizeStore {
        DurableResizeStore::new(
            "amaterasu.session-lifecycle",
            intent,
            "resize-test".into(),
            None,
            5000,
            |_| true,
        )
        .unwrap()
    }
    #[test]
    fn durable_pending_commit_and_completed_lineage_fence_replay() {
        let (intent, updated) = fixture();
        let mut store = store(intent.clone());
        let mut fake = Fake::default();
        fake.values.insert(
            store.key.clone(),
            serde_json::to_value(&intent.prior).unwrap(),
        );
        let begin = ResizeStoreCommand::Begin {
            intent: intent.clone(),
        };
        assert_eq!(
            fake.run(&mut store, begin.clone()),
            ResizeStoreProgress::Applied
        );
        let pending = decode_envelope(fake.values[&store.key].clone()).unwrap();
        assert_eq!(pending.active.unwrap().state, ResizeRecordState::Pending);
        let mut restarted = self::store(intent.clone());
        assert_eq!(
            fake.run(&mut restarted, begin.clone()),
            ResizeStoreProgress::ExistingPending
        );
        assert_eq!(
            fake.run(
                &mut store,
                ResizeStoreCommand::Commit {
                    intent: intent.clone(),
                    updated: updated.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        let committed = decode_envelope(fake.values[&store.key].clone()).unwrap();
        assert_eq!(committed.obligation, updated);
        assert_eq!(
            committed.active.unwrap().state,
            ResizeRecordState::Committed
        );
        assert_eq!(
            fake.run(
                &mut store,
                ResizeStoreCommand::Finish {
                    intent: intent.clone(),
                    updated: updated.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        let done = decode_envelope(fake.values[&store.key].clone()).unwrap();
        assert!(done.active.is_none());
        assert_eq!(done.lineage.len(), 1);
        let mut restarted = self::store(intent);
        assert_eq!(
            fake.run(&mut restarted, begin),
            ResizeStoreProgress::ExistingPending
        );
    }
    #[test]
    fn stale_prior_invalid_replacement_and_cas_conflict_fail_safely() {
        let (intent, mut updated) = fixture();
        let mut store = store(intent.clone());
        let mut fake = Fake {
            conflict: true,
            ..Default::default()
        };
        fake.values.insert(
            store.key.clone(),
            serde_json::to_value(&intent.prior).unwrap(),
        );
        assert_eq!(
            fake.run(
                &mut store,
                ResizeStoreCommand::Begin {
                    intent: intent.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        updated.identity = "different".into();
        assert_eq!(
            fake.run(
                &mut store,
                ResizeStoreCommand::Commit {
                    intent: intent.clone(),
                    updated
                }
            ),
            ResizeStoreProgress::Unknown
        );
        let pending = decode_envelope(fake.values[&store.key].clone()).unwrap();
        assert_eq!(pending.obligation, intent.prior);
        assert_eq!(pending.active.unwrap().state, ResizeRecordState::Pending);
        assert!(
            DurableResizeStore::new("other", intent, "test".into(), None, 5000, |_| true).is_err()
        );
    }
    #[test]
    fn malformed_envelope_never_downgrades_to_legacy() {
        let (intent, _) = fixture();
        let mut value = serde_json::to_value(intent.prior).unwrap();
        value["format_version"] = json!(99);
        assert!(decode_envelope(value).is_err());
    }
    #[test]
    fn second_resize_preserves_linked_lineage_and_rejects_tampering() {
        let (intent, updated) = fixture();
        let mut fake = Fake::default();
        let mut first = store(intent.clone());
        fake.values.insert(
            first.key.clone(),
            serde_json::to_value(&intent.prior).unwrap(),
        );
        assert_eq!(
            fake.run(
                &mut first,
                ResizeStoreCommand::Begin {
                    intent: intent.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        assert_eq!(
            fake.run(
                &mut first,
                ResizeStoreCommand::Commit {
                    intent: intent.clone(),
                    updated: updated.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        assert_eq!(
            fake.run(
                &mut first,
                ResizeStoreCommand::Finish {
                    intent: intent.clone(),
                    updated: updated.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        let mut next = intent.clone();
        next.request.provider_sequence = 3;
        next.request.operation_id = "op-3".into();
        next.operation_id = "resize.def".into();
        next.prior = updated.clone();
        next.desired.width = 1920;
        next.desired.height = 1080;
        next.request.approved_plan.as_mut().unwrap().constraints["virtual_reconfigure"] =
            json!({"session_target":next.session_target,"prior":next.prior,"desired":next.desired});
        let mut result = updated.clone();
        result.width = 1920;
        result.height = 1080;
        result.geometry_revision = 5;
        let borrow = result.borrow.as_mut().unwrap();
        borrow.borrow_id = "d".repeat(64);
        borrow.observed_output.width = 1920;
        borrow.observed_output.height = 1080;
        borrow.mutation_domain.revision = 5;
        let mut second = store(next.clone());
        assert_eq!(
            fake.run(
                &mut second,
                ResizeStoreCommand::Begin {
                    intent: next.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        assert_eq!(
            fake.run(
                &mut second,
                ResizeStoreCommand::Commit {
                    intent: next.clone(),
                    updated: result.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        assert_eq!(
            fake.run(
                &mut second,
                ResizeStoreCommand::Finish {
                    intent: next,
                    updated: result
                }
            ),
            ResizeStoreProgress::Applied
        );
        let saved = fake.values[&first.key].clone();
        let decoded = decode_envelope(saved.clone()).unwrap();
        assert_eq!(decoded.lineage.len(), 1);
        assert!(decoded.checkpoint.is_some());
        let mut tampered = saved;
        tampered["lineage"][0]["prior"]["reference_id"] = json!("foreign");
        assert!(decode_envelope(tampered).is_err());
    }
    #[test]
    fn lost_write_acknowledgement_fences_restart() {
        let (intent, _) = fixture();
        let mut first = store(intent.clone());
        let mut fake = Fake {
            lost_ack: true,
            ..Default::default()
        };
        fake.values.insert(
            first.key.clone(),
            serde_json::to_value(&intent.prior).unwrap(),
        );
        let begin = ResizeStoreCommand::Begin {
            intent: intent.clone(),
        };
        assert_eq!(
            fake.run(&mut first, begin.clone()),
            ResizeStoreProgress::Unknown
        );
        let persisted = decode_envelope(fake.values[&first.key].clone()).unwrap();
        assert_eq!(persisted.active.unwrap().state, ResizeRecordState::Pending);
        let mut restarted = store(intent);
        assert_eq!(
            fake.run(&mut restarted, begin),
            ResizeStoreProgress::ExistingPending
        );
    }
    #[test]
    fn lost_commit_acknowledgement_keeps_new_lease_fenced() {
        let (intent, updated) = fixture();
        let mut first = store(intent.clone());
        let mut fake = Fake::default();
        fake.values.insert(
            first.key.clone(),
            serde_json::to_value(&intent.prior).unwrap(),
        );
        assert_eq!(
            fake.run(
                &mut first,
                ResizeStoreCommand::Begin {
                    intent: intent.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        fake.lost_ack = true;
        assert_eq!(
            fake.run(
                &mut first,
                ResizeStoreCommand::Commit {
                    intent: intent.clone(),
                    updated: updated.clone()
                }
            ),
            ResizeStoreProgress::Unknown
        );
        let persisted = decode_envelope(fake.values[&first.key].clone()).unwrap();
        assert_eq!(persisted.obligation, updated);
        assert_eq!(
            persisted.active.unwrap().state,
            ResizeRecordState::Committed
        );
        let mut restarted = store(intent.clone());
        assert_eq!(
            fake.run(&mut restarted, ResizeStoreCommand::Begin { intent }),
            ResizeStoreProgress::ExistingPending
        );
    }
    #[test]
    fn checkpoint_survives_twelve_resizes_and_preserves_root() {
        let (mut intent, _) = fixture();
        intent.request.approved_plan.as_mut().unwrap().constraints["production_padding"] =
            json!("x".repeat(3500));
        assert!(serde_json::to_vec(&intent.request).unwrap().len() >= 4380);
        let root = intent.prior.clone();
        let mut fake = Fake::default();
        let first = store(intent.clone());
        fake.values
            .insert(first.key.clone(), serde_json::to_value(&root).unwrap());
        let key = first.key;
        for n in 0..12u64 {
            intent.request.provider_sequence = 2 + n;
            intent.request.operation_id = format!("op-{}", n + 2);
            intent.operation_id = format!("resize.{n}");
            intent.desired.width = if n % 2 == 0 { 1280 } else { 1920 };
            intent.desired.height = if n % 2 == 0 { 720 } else { 1080 };
            intent.request.approved_plan.as_mut().unwrap().constraints["virtual_reconfigure"] = json!({"session_target":intent.session_target,"prior":intent.prior,"desired":intent.desired});
            let mut updated = intent.prior.clone();
            updated.width = intent.desired.width;
            updated.height = intent.desired.height;
            let b = updated.borrow.as_mut().unwrap();
            b.borrow_id = format!("{:064x}", n + 1);
            b.observed_output.width = updated.width;
            b.observed_output.height = updated.height;
            b.mutation_domain.revision += 1;
            updated.geometry_revision = b.mutation_domain.revision;
            let mut current = store(intent.clone());
            assert_eq!(
                fake.run(
                    &mut current,
                    ResizeStoreCommand::Begin {
                        intent: intent.clone()
                    }
                ),
                ResizeStoreProgress::Applied
            );
            assert_eq!(
                fake.run(
                    &mut current,
                    ResizeStoreCommand::Commit {
                        intent: intent.clone(),
                        updated: updated.clone()
                    }
                ),
                ResizeStoreProgress::Applied,
                "commit cycle {n} value size {}",
                serde_json::to_vec(&fake.values[&key]).unwrap().len()
            );
            assert_eq!(
                fake.run(
                    &mut current,
                    ResizeStoreCommand::Finish {
                        intent: intent.clone(),
                        updated: updated.clone()
                    }
                ),
                ResizeStoreProgress::Applied
            );
            intent.prior = updated;
        }
        let saved = decode_envelope(fake.values[&key].clone()).unwrap();
        assert_eq!(saved.checkpoint.as_ref().unwrap().prior, root);
        assert_eq!(saved.lineage.len(), 1);
        assert_eq!(saved.lineage[0].provider_sequence, 13);
        assert_eq!(saved.obligation, intent.prior);
        let mut planned = root;
        planned.borrow = None;
        assert!(crate::virtual_callback::lineage_authorizes(
            &saved,
            &intent.session_target,
            &planned
        ));
    }
    fn normal_reader(
        fake: &mut Fake,
        target: &LifecycleTarget,
    ) -> crate::durable_store::LoadProgress<VirtualObligation> {
        use crate::{
            durable_store::{LoadProgress, VerifiedTarget, VirtualDurableStateStore},
            receipt_store::VerifiedEpoch,
        };
        let key = format!(
            "target-{:x}",
            Sha256::digest(serde_json::to_vec(target).unwrap())
        );
        let epoch = VerifiedEpoch::authenticate("epoch".into(), |_| true).unwrap();
        let target = VerifiedTarget::authenticate(key, |_| true).unwrap();
        let mut reader =
            VirtualDurableStateStore::new(epoch, target, "reader".into(), None, 5000).unwrap();
        reader.start_load().unwrap();
        for now in 0..50 {
            reader.advance(now, &mut |c| fake.send(c));
            let state = reader.poll_load();
            if !matches!(state, LoadProgress::Waiting) {
                return state;
            }
        }
        panic!("reader stuck")
    }
    #[test]
    fn ordinary_reader_fences_pending_and_committed_across_restart() {
        use crate::durable_store::LoadProgress;
        let (intent, updated) = fixture();
        let mut writer = store(intent.clone());
        let mut fake = Fake::default();
        fake.values.insert(
            writer.key.clone(),
            serde_json::to_value(&intent.prior).unwrap(),
        );
        assert_eq!(
            fake.run(
                &mut writer,
                ResizeStoreCommand::Begin {
                    intent: intent.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        assert!(matches!(
            normal_reader(&mut fake, &intent.session_target),
            LoadProgress::Unknown
        ));
        assert_eq!(
            fake.run(
                &mut writer,
                ResizeStoreCommand::Commit {
                    intent: intent.clone(),
                    updated: updated.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        assert!(matches!(
            normal_reader(&mut fake, &intent.session_target),
            LoadProgress::Unknown
        ));
        assert_eq!(
            fake.run(
                &mut writer,
                ResizeStoreCommand::Finish {
                    intent: intent.clone(),
                    updated: updated.clone()
                }
            ),
            ResizeStoreProgress::Applied
        );
        assert!(
            matches!(normal_reader(&mut fake,&intent.session_target),LoadProgress::Found(v) if v==updated)
        );
    }
    #[test]
    fn compact_provenance_rejects_corrupt_native_transition() {
        let (intent, updated) = fixture();
        let record = ResizeRecord {
            intent,
            updated: Some(updated),
            state: ResizeRecordState::Completed,
        };
        let settled = SettledResize::from_record(record).unwrap();
        let envelope = ResizeEnvelope {
            format_version: 1,
            obligation: settled.updated.clone(),
            active: None,
            checkpoint: None,
            lineage: vec![settled],
        };
        let good = serde_json::to_value(envelope).unwrap();
        assert!(decode_envelope(good.clone()).is_ok());
        for (path, value) in [
            ("/lineage/0/updated/name", json!("tampered")),
            ("/lineage/0/updated/reference_released", json!(true)),
            ("/lineage/0/updated/width", json!(1)),
            ("/lineage/0/updated/geometry_revision", json!(999)),
            ("/lineage/0/updated/borrow/borrow_id", json!("a".repeat(64))),
            (
                "/lineage/0/updated/borrow/mutation_domain/revision",
                json!(3),
            ),
            (
                "/lineage/0/updated/borrow/observed_output/registry_global",
                json!(99),
            ),
            ("/lineage/0/session_target/generation", json!(0)),
        ] {
            let mut corrupt = good.clone();
            *corrupt.pointer_mut(path).unwrap() = value;
            assert!(decode_envelope(corrupt).is_err(), "accepted {path}");
        }
    }
    #[test]
    fn legacy_full_settled_record_decodes_into_compact_checkpoint() {
        let (intent, updated) = fixture();
        let legacy = ResizeRecord {
            intent: intent.clone(),
            updated: Some(updated.clone()),
            state: ResizeRecordState::Completed,
        };
        let value = json!({"format_version":1,"obligation":updated,"active":null,"checkpoint":null,"lineage":[legacy]});
        let decoded = decode_envelope(value).unwrap();
        assert_eq!(
            decoded.lineage[0].request_digest,
            request_digest(&intent.request).unwrap()
        );
        let compact = serde_json::to_value(decoded).unwrap();
        assert!(compact["lineage"][0].get("intent").is_none());
    }
}
