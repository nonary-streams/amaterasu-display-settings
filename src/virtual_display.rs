//! Bounded broker client for the public virtual-display service.
//!
//! A successful broker exchange is not a completed native display operation.
//! Each call to [`PendingCall::poll`] performs at most one broker command.

use amaterasu_module_sdk::{Command, ModuleResult, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SERVICE: &str = "amaterasu.virtual-display/1";
const MAX_ATTEMPTS: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayReference {
    pub identity: String,
    pub reference_id: String,
}

impl DisplayReference {
    pub fn validate(&self) -> Result<(), &'static str> {
        let identity = self.identity.as_bytes();
        let valid_uuid = identity.len() == 36
            && identity.iter().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    *byte == b'-'
                } else {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
                }
            })
            && identity.iter().any(|byte| *byte != b'0' && *byte != b'-');
        if !valid_uuid
            || self.reference_id.is_empty()
            || self.reference_id.len() > 128
            || !self
                .reference_id
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
        {
            return Err("invalid display reference");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateDisplay {
    pub reference: DisplayReference,
    pub width: u32,
    pub height: u32,
    pub refresh_millihz: u32,
    pub name: String,
    pub hdr_enabled: bool,
    /// Provider support for nonzero scales depends on the platform.
    pub scale: Option<i32>,
}

impl CreateDisplay {
    fn validate(&self) -> Result<(), &'static str> {
        self.reference.validate()?;
        if !(320..=7680).contains(&self.width)
            || !(200..=4320).contains(&self.height)
            || !(1000..=1_000_000).contains(&self.refresh_millihz)
            || self.name.is_empty()
            || self.name.len() > 31
            || !self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err("invalid display specification");
        }
        if self.scale.is_some_and(|scale| {
            ![
                -1, 0, 100, 125, 150, 175, 200, 225, 250, 300, 350, 400, 450, 500,
            ]
            .contains(&scale)
        }) {
            return Err("invalid display scale");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisplayRequest {
    ReconfigureStatus {
        reference: DisplayReference,
        operation_id: String,
        borrow_id: String,
        domain_id: String,
        revision: u64,
    },
    Reconfigure {
        reference: DisplayReference,
        operation_id: String,
        borrow_id: String,
        width: u32,
        height: u32,
        refresh_millihz: u32,
        domain_id: String,
        revision: u64,
    },
    Create(CreateDisplay),
    CreatePlanned {
        create: CreateDisplay,
        layout: String,
        domain_id: String,
        revision: u64,
    },
    Status(DisplayReference),
    Remove(DisplayReference),
    Borrow(DisplayReference),
    ValidateBorrow {
        reference: DisplayReference,
        borrow_id: String,
    },
    ReleaseBorrow {
        reference: DisplayReference,
        borrow_id: String,
    },
}

impl DisplayRequest {
    fn reference(&self) -> &DisplayReference {
        match self {
            Self::Create(create) | Self::CreatePlanned { create, .. } => &create.reference,
            Self::Status(reference)
            | Self::Remove(reference)
            | Self::Borrow(reference)
            | Self::Reconfigure { reference, .. }
            | Self::ReconfigureStatus { reference, .. }
            | Self::ValidateBorrow { reference, .. }
            | Self::ReleaseBorrow { reference, .. } => reference,
        }
    }

    fn payload(&self) -> Result<Value, &'static str> {
        self.reference().validate()?;
        let reference = self.reference();
        Ok(match self {
            Self::ReconfigureStatus {
                operation_id,
                borrow_id,
                domain_id,
                revision,
                ..
            } => {
                if operation_id.is_empty()
                    || operation_id.len() > 128
                    || !operation_id.bytes().all(|b| b.is_ascii_graphic())
                    || !valid_borrow_id(borrow_id)
                    || !valid_domain_id(domain_id)
                {
                    return Err("invalid reconfiguration status");
                }
                json!({"action":"reconfigure_status","operation_id":operation_id,"identity":reference.identity,"reference_id":reference.reference_id,"borrow_id":borrow_id,"expected_topology_domain_id":domain_id,"expected_topology_revision":revision})
            }
            Self::Reconfigure {
                operation_id,
                borrow_id,
                width,
                height,
                refresh_millihz,
                domain_id,
                revision,
                ..
            } => {
                if operation_id.is_empty()
                    || operation_id.len() > 128
                    || !operation_id.bytes().all(|b| b.is_ascii_graphic())
                    || !valid_borrow_id(borrow_id)
                    || !valid_domain_id(domain_id)
                    || !(320..=7680).contains(width)
                    || !(200..=4320).contains(height)
                    || !(1000..=1_000_000).contains(refresh_millihz)
                {
                    return Err("invalid reconfiguration");
                }
                json!({"action":"reconfigure","operation_id":operation_id,"identity":reference.identity,"reference_id":reference.reference_id,"borrow_id":borrow_id,"width":width,"height":height,"refresh_millihz":refresh_millihz,"expected_topology_domain_id":domain_id,"expected_topology_revision":revision})
            }
            Self::Create(create) | Self::CreatePlanned { create, .. } => {
                create.validate()?;
                let mut value = json!({"action":"create", "identity":reference.identity,
                    "reference_id":reference.reference_id, "width":create.width,
                    "height":create.height, "refresh_millihz":create.refresh_millihz,
                    "name":create.name, "hdr_enabled":create.hdr_enabled});
                if let Some(scale) = create.scale {
                    value["dd_virtual_display_scale"] = json!(scale);
                }
                if let Self::CreatePlanned {
                    layout,
                    domain_id,
                    revision,
                    ..
                } = self
                {
                    if !matches!(layout.as_str(), "exclusive" | "extended")
                        || !valid_domain_id(domain_id)
                    {
                        return Err("invalid topology plan");
                    }
                    value["virtual_display_layout"] = json!(layout);
                    value["expected_topology_domain_id"] = json!(domain_id);
                    value["expected_topology_revision"] = json!(revision);
                }
                value
            }
            Self::Status(_) => {
                json!({"action":"status", "identity":reference.identity, "reference_id":reference.reference_id})
            }
            Self::Remove(_) => {
                json!({"action":"remove", "identity":reference.identity, "reference_id":reference.reference_id})
            }
            Self::Borrow(_) => {
                json!({"action":"borrow","identity":reference.identity,"reference_id":reference.reference_id})
            }
            Self::ValidateBorrow { borrow_id, .. } | Self::ReleaseBorrow { borrow_id, .. } => {
                if !valid_borrow_id(borrow_id) {
                    return Err("invalid borrow id");
                }
                json!({"action": if matches!(self, Self::ValidateBorrow { .. }) { "validate_borrow" } else { "release_borrow" }, "identity":reference.identity, "reference_id":reference.reference_id, "borrow_id":borrow_id})
            }
        })
    }
}

fn valid_borrow_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_domain_id(id: &str) -> bool {
    id.starts_with("provider_session:")
        && id.len() > 17
        && id.len() <= 256
        && !id.chars().any(char::is_control)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedOutput {
    pub version: u32,
    pub protocol: String,
    pub compositor_id: String,
    pub registry_global: u32,
    pub output_name: String,
    pub width: u32,
    pub height: u32,
    pub refresh_millihz: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MutationDomain {
    pub id: String,
    pub revision: u64,
    pub borrowers: u64,
    pub pending_mutations: u64,
    pub scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisplayBorrow {
    pub borrow_id: String,
    pub observed_output: ObservedOutput,
    pub mutation_domain: MutationDomain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyDisplay {
    pub device_path: String,
    pub active: bool,
    /// On Linux this is the provider's capture routing name; Windows may omit it.
    pub capture_output: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisplayOutcome {
    /// Ownership exists, but monitor identity has not yet been published.
    Creating,
    /// Provider reports monitor identity published; capture is not established.
    Ready(ReadyDisplay),
    /// The queried caller reference is absent; other references may remain.
    ReferenceAbsent {
        monitor_present: bool,
    },
    /// Reference was released but native cleanup is not yet confirmed.
    CleanupPending,
    /// Provider confirms this caller's reference is gone and another remains.
    ReferenceReleased,
    /// Provider confirms no monitor for this caller and identity exists.
    Removed,
    /// The provider did not establish successful completion.
    ProviderError(String),
    Borrowed(DisplayBorrow),
    ReconfigurePending,
    BorrowReleased(MutationDomain),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallProgress {
    Waiting,
    Complete(DisplayOutcome),
    /// The initial broker explicitly rejected admission before any uncertain send.
    Rejected(String),
    /// Admission, provider effect, result release, or cleanup could not be proven.
    Unknown,
}

/// Holds one immutable broker operation, including its stable operation ID.
/// The caller must supply a unique operation ID for each distinct logical call.
pub struct PendingCall {
    command: Command,
    request: DisplayRequest,
    deadline_ms: u64,
    request_id: Option<u64>,
    uncertain_admission: bool,
    failures: u8,
    result: Option<DisplayOutcome>,
    invalid_result: bool,
    finished: Option<CallProgress>,
}

impl PendingCall {
    pub fn new(
        request: DisplayRequest,
        operation_id: String,
        parent: Option<u64>,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        if operation_id.is_empty()
            || operation_id.len() > 128
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-' | b'/')
            })
            || !(1..=30_000).contains(&timeout_ms)
        {
            return Err("invalid broker operation");
        }
        let payload = request.payload()?;
        Ok(Self {
            command: Command::Request {
                service: SERVICE.into(),
                payload,
                timeout_ms,
                operation_id,
                parent,
            },
            request,
            deadline_ms: now_ms.saturating_add(timeout_ms),
            request_id: None,
            uncertain_admission: false,
            failures: 0,
            result: None,
            invalid_result: false,
            finished: None,
        })
    }

    /// Broker request ID, when admission was observed. Retain this for explicit
    /// broker reconciliation if polling ends in an unknown state.
    pub fn request_id(&self) -> Option<u64> {
        self.request_id
    }

    /// Parsed result before broker release. Persist newly acquired borrow IDs
    /// before polling again; only `Complete` confirms result release.
    pub fn tentative(&self) -> Option<&DisplayOutcome> {
        self.result.as_ref()
    }

    /// The supplied clock must be monotonic and use the same units as `new`.
    /// Transport errors and deadlines retain unknown outcome; callers must reconcile
    /// using the same display reference and must not infer cleanup succeeded.
    pub fn poll(
        &mut self,
        now_ms: u64,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> CallProgress {
        if let Some(done) = &self.finished {
            return done.clone();
        }
        if now_ms >= self.deadline_ms || self.failures >= MAX_ATTEMPTS {
            self.finished = Some(CallProgress::Unknown);
            return CallProgress::Unknown;
        }
        if let Some(request_id) = self.request_id {
            if self.result.is_some() || self.invalid_result {
                return match send(Command::ReleaseResult {
                    request: request_id,
                }) {
                    Ok(Response::Ok) => {
                        let done = self
                            .result
                            .clone()
                            .map_or(CallProgress::Unknown, CallProgress::Complete);
                        self.finished = Some(done.clone());
                        done
                    }
                    _ => {
                        self.failures += 1;
                        CallProgress::Waiting
                    }
                };
            }
            match send(Command::TakeResult {
                request: request_id,
            }) {
                Ok(Response::Pending) => CallProgress::Waiting,
                Ok(Response::Result { payload }) => {
                    self.result = parse_response(&self.request, &payload);
                    self.invalid_result = self.result.is_none();
                    CallProgress::Waiting
                }
                _ => {
                    self.failures += 1;
                    CallProgress::Waiting
                }
            }
        } else {
            match send(self.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.request_id = Some(id);
                    self.failures = 0;
                    CallProgress::Waiting
                }
                Ok(Response::Error { code, .. }) if !self.uncertain_admission => {
                    let done = CallProgress::Rejected(code);
                    self.finished = Some(done.clone());
                    done
                }
                _ => {
                    self.uncertain_admission = true;
                    self.failures += 1;
                    CallProgress::Waiting
                }
            }
        }
    }
}

fn parse_response(request: &DisplayRequest, payload: &Value) -> Option<DisplayOutcome> {
    if !payload.get("ok")?.as_bool()? {
        return Some(DisplayOutcome::ProviderError(
            payload.get("code")?.as_str()?.to_owned(),
        ));
    }
    let identity = &request.reference().identity;
    match request {
        DisplayRequest::Create(create) | DisplayRequest::CreatePlanned { create, .. } => {
            if !payload.get("reference_owned")?.as_bool()? {
                return None;
            }
            let monitor = payload.get("monitor")?;
            if let DisplayRequest::CreatePlanned { layout, .. } = request
                && monitor.get("virtual_display_layout")?.as_str()? != layout
            {
                return None;
            }
            if let DisplayRequest::CreatePlanned { .. } = request
                && create.scale.is_some_and(|scale| {
                    monitor
                        .get("dd_virtual_display_scale")
                        .and_then(Value::as_i64)
                        != Some(i64::from(scale))
                })
            {
                return None;
            }
            if !monitor_matches(monitor, identity) {
                return None;
            }
            let spec = monitor.get("specification")?;
            if spec.get("width")?.as_u64()? != u64::from(create.width)
                || spec.get("height")?.as_u64()? != u64::from(create.height)
                || spec.get("refresh_millihz")?.as_u64()? != u64::from(create.refresh_millihz)
                || spec.get("name")?.as_str()? != create.name
                || spec.get("hdr_enabled")?.as_bool()? != create.hdr_enabled
            {
                return None;
            }
            parse_monitor(monitor)
        }
        DisplayRequest::Status(_) => {
            let owned = payload.get("reference_owned")?.as_bool()?;
            let monitors = payload.get("monitors")?.as_array()?;
            if monitors.len() > 1 {
                return None;
            }
            if let Some(monitor) = monitors.first() {
                if !monitor_matches(monitor, identity) {
                    return None;
                }
                if let Some(value) = monitor.get("reference_owned")
                    && value.as_bool()? != owned
                {
                    return None;
                }
                if owned {
                    parse_monitor(monitor)
                } else {
                    Some(DisplayOutcome::ReferenceAbsent {
                        monitor_present: true,
                    })
                }
            } else if owned {
                None
            } else {
                Some(DisplayOutcome::ReferenceAbsent {
                    monitor_present: false,
                })
            }
        }
        DisplayRequest::Remove(_) => {
            if payload.get("removed").and_then(Value::as_bool) == Some(true) {
                if payload.get("identity")?.as_str()? != identity {
                    return None;
                }
                return Some(DisplayOutcome::Removed);
            }
            if payload.get("removed").and_then(Value::as_bool) == Some(false)
                && payload.get("identity").is_some()
            {
                if payload.get("identity")?.as_str()? != identity
                    || payload.get("reference_owned")?.as_bool()?
                {
                    return None;
                }
                return Some(if payload.get("reference_released")?.as_bool()? {
                    DisplayOutcome::ReferenceReleased
                } else {
                    DisplayOutcome::ReferenceAbsent {
                        monitor_present: true,
                    }
                });
            }
            let monitor = payload.get("monitor")?;
            if !monitor_matches(monitor, identity) || payload.get("reference_owned")?.as_bool()? {
                return None;
            }
            match monitor.get("state")?.as_str()? {
                "removing" => Some(DisplayOutcome::CleanupPending),
                "cleanup_failed" => Some(DisplayOutcome::ProviderError("cleanup_failed".into())),
                _ => None,
            }
        }
        DisplayRequest::Borrow(_)
        | DisplayRequest::ValidateBorrow { .. }
        | DisplayRequest::Reconfigure { .. }
        | DisplayRequest::ReconfigureStatus { .. } => {
            if let DisplayRequest::Reconfigure { operation_id, .. }
            | DisplayRequest::ReconfigureStatus { operation_id, .. } = request
            {
                if payload.get("operation_id")?.as_str()? != operation_id {
                    return None;
                }
                match payload.get("state")?.as_str()? {
                    "pending" => return Some(DisplayOutcome::ReconfigurePending),
                    "succeeded" => {}
                    _ => return None,
                }
            }
            let borrow_id = payload.get("borrow_id")?.as_str()?.to_owned();
            if !valid_borrow_id(&borrow_id) {
                return None;
            }
            if let DisplayRequest::ValidateBorrow {
                borrow_id: expected,
                ..
            } = request
                && &borrow_id != expected
            {
                return None;
            }
            let observed_output: ObservedOutput =
                serde_json::from_value(payload.get("observed_output")?.clone()).ok()?;
            let mutation_domain = parse_domain(payload)?;
            if observed_output.version != 1
                || observed_output.protocol != "wayland-wl-output"
                || !valid_borrow_id(&observed_output.compositor_id)
                || observed_output.registry_global == 0
                || observed_output.width == 0
                || observed_output.height == 0
                || observed_output.refresh_millihz == 0
                || !valid_output_name(&observed_output.output_name)
            {
                return None;
            }
            Some(DisplayOutcome::Borrowed(DisplayBorrow {
                borrow_id,
                observed_output,
                mutation_domain,
            }))
        }
        DisplayRequest::ReleaseBorrow { .. } => {
            if payload.get("released")?.as_bool()? {
                Some(DisplayOutcome::BorrowReleased(parse_domain(payload)?))
            } else {
                None
            }
        }
    }
}

fn parse_domain(payload: &Value) -> Option<MutationDomain> {
    let domain: MutationDomain =
        serde_json::from_value(payload.get("mutation_domain")?.clone()).ok()?;
    if domain.scope != "provider_session" || !valid_domain_id(&domain.id) {
        return None;
    }
    Some(domain)
}
fn valid_output_name(name: &str) -> bool {
    name.strip_prefix("Virtual-").is_some_and(|value| {
        !value.starts_with('0')
            && value.bytes().all(|b| b.is_ascii_digit())
            && value.parse::<i32>().is_ok_and(|n| n > 0)
    })
}

fn monitor_matches(monitor: &Value, identity: &str) -> bool {
    monitor
        .get("specification")
        .and_then(|spec| spec.get("identity"))
        .and_then(Value::as_str)
        == Some(identity)
}

fn parse_monitor(monitor: &Value) -> Option<DisplayOutcome> {
    if !monitor.get("error").is_none_or(Value::is_null) {
        return None;
    }
    match monitor.get("state")?.as_str()? {
        "creating" => Some(DisplayOutcome::Creating),
        "ready" => {
            let ready = monitor.get("ready")?;
            let device_path = ready.get("device_path")?.as_str()?.to_owned();
            if device_path.is_empty() {
                return None;
            }
            let active = ready.get("active")?.as_bool()?;
            let capture_output = match monitor.get("capture_output") {
                None | Some(Value::Null) => None,
                Some(value) => Some(value.as_str()?.to_owned()),
            };
            if capture_output.as_deref() == Some("") {
                return None;
            }
            Some(DisplayOutcome::Ready(ReadyDisplay {
                device_path,
                active,
                capture_output,
            }))
        }
        "recovered" | "reclaim_pending" | "removing" | "cleanup_failed" | "ownership_conflict" => {
            Some(DisplayOutcome::ProviderError(
                monitor.get("state")?.as_str()?.to_owned(),
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn reference() -> DisplayReference {
        DisplayReference {
            identity: "9c1d707f-7229-4fc4-b6e2-91f80c626a09".into(),
            reference_id: "session-42".into(),
        }
    }
    fn create() -> CreateDisplay {
        CreateDisplay {
            reference: reference(),
            width: 1920,
            height: 1080,
            refresh_millihz: 60000,
            name: "Amaterasu".into(),
            hdr_enabled: false,
            scale: None,
        }
    }
    fn monitor(state: &str) -> Value {
        json!({"specification":{"identity":reference().identity,"width":1920,"height":1080,"refresh_millihz":60000,"name":"Amaterasu","hdr_enabled":false},"reference_owned":true,"state":state,"error":null,"ready":null})
    }
    fn response(payload: Value) -> Response {
        Response::Result { payload }
    }

    #[test]
    fn wire_create_polls_accepted_pending_result_and_releases() {
        let mut call = PendingCall::new(
            DisplayRequest::Create(create()),
            "create.42".into(),
            Some(7),
            5000,
            0,
        )
        .unwrap();
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 9 }),
            Ok(Response::Pending),
            Ok(response(
                json!({"ok":true,"reference_owned":true,"monitor":monitor("creating")}),
            )),
            Ok(Response::Ok),
        ]);
        let mut commands = Vec::new();
        let mut send = |command: Command| {
            commands.push(command);
            replies.pop_front().unwrap()
        };
        for tick in 0..3 {
            assert_eq!(call.poll(tick, &mut send), CallProgress::Waiting);
        }
        assert_eq!(
            call.poll(3, &mut send),
            CallProgress::Complete(DisplayOutcome::Creating)
        );
        match &commands[0] {
            Command::Request {
                service,
                payload,
                operation_id,
                parent,
                ..
            } => {
                assert_eq!(service, SERVICE);
                assert_eq!(operation_id, "create.42");
                assert_eq!(*parent, Some(7));
                assert_eq!(payload["reference_id"], "session-42");
                assert!(payload.get("dd_virtual_display_scale").is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(commands[1], Command::TakeResult { request: 9 }));
        assert!(matches!(commands[3], Command::ReleaseResult { request: 9 }));
    }

    #[test]
    fn lost_admission_reuses_same_operation_and_never_turns_later_rejection_into_success() {
        let mut call = PendingCall::new(
            DisplayRequest::Remove(reference()),
            "remove.42".into(),
            None,
            5000,
            0,
        )
        .unwrap();
        let mut commands = Vec::new();
        let mut send = |command: Command| {
            commands.push(command);
            Err("transport lost".into())
        };
        assert_eq!(call.poll(1, &mut send), CallProgress::Waiting);
        assert_eq!(call.poll(2, &mut send), CallProgress::Waiting);
        assert_eq!(call.poll(3, &mut send), CallProgress::Waiting);
        assert_eq!(call.poll(4, &mut send), CallProgress::Unknown);
        let ids: Vec<_> = commands
            .iter()
            .map(|command| match command {
                Command::Request {
                    operation_id,
                    payload,
                    ..
                } => {
                    assert_eq!(payload["reference_id"], "session-42");
                    operation_id.as_str()
                }
                _ => panic!("unexpected command"),
            })
            .collect();
        assert_eq!(ids, vec!["remove.42"; 3]);
    }

    #[test]
    fn status_requires_exact_identity_and_consistent_reference_ownership() {
        let request = DisplayRequest::Status(reference());
        let mut ready = monitor("ready");
        ready["ready"] = json!({"device_path":"Virtual-1","active":true});
        ready["capture_output"] = json!("kwin:Virtual-1");
        let payload = json!({"ok":true,"reference_owned":true,"monitors":[ready.clone()]});
        assert!(matches!(
            parse_response(&request, &payload),
            Some(DisplayOutcome::Ready(ReadyDisplay { active: true, .. }))
        ));
        ready["reference_owned"] = json!(false);
        assert_eq!(
            parse_response(
                &request,
                &json!({"ok":true,"reference_owned":true,"monitors":[ready]})
            ),
            None
        );
        assert_eq!(
            parse_response(
                &request,
                &json!({"ok":true,"reference_owned":false,"monitors":[]})
            ),
            Some(DisplayOutcome::ReferenceAbsent {
                monitor_present: false
            })
        );
        assert_eq!(
            parse_response(
                &request,
                &json!({"ok":true,"reference_owned":true,"monitors":[]})
            ),
            None
        );
    }

    #[test]
    fn remove_distinguishes_reference_release_cleanup_and_absence() {
        let request = DisplayRequest::Remove(reference());
        let identity = reference().identity;
        assert_eq!(
            parse_response(
                &request,
                &json!({"ok":true,"removed":false,"identity":identity,"reference_released":true,"reference_owned":false})
            ),
            Some(DisplayOutcome::ReferenceReleased)
        );
        assert_eq!(
            parse_response(
                &request,
                &json!({"ok":true,"removed":false,"monitor":monitor("removing"),"reference_owned":false})
            ),
            Some(DisplayOutcome::CleanupPending)
        );
        assert_eq!(
            parse_response(
                &request,
                &json!({"ok":true,"removed":true,"identity":identity})
            ),
            Some(DisplayOutcome::Removed)
        );
        assert_eq!(
            parse_response(
                &request,
                &json!({"ok":true,"removed":true,"identity":"wrong"})
            ),
            None
        );
        assert_eq!(
            parse_response(
                &request,
                &json!({"ok":true,"removed":false,"identity":identity,"reference_released":false,"reference_owned":false})
            ),
            Some(DisplayOutcome::ReferenceAbsent {
                monitor_present: true
            })
        );
    }

    #[test]
    fn uncertain_and_malformed_responses_are_never_cleanup_success() {
        let request = DisplayRequest::Create(create());
        assert_eq!(
            parse_response(
                &request,
                &json!({"ok":true,"reference_owned":true,"monitor":monitor("future_state")})
            ),
            None
        );
        assert_eq!(
            parse_response(&request, &json!({"ok":false,"code":"unsupported_scale"})),
            Some(DisplayOutcome::ProviderError("unsupported_scale".into()))
        );
        let mut call = PendingCall::new(
            DisplayRequest::Remove(reference()),
            "remove.43".into(),
            None,
            10,
            0,
        )
        .unwrap();
        let mut send = |_: Command| Ok(Response::Accepted { id: 4 });
        assert_eq!(call.poll(1, &mut send), CallProgress::Waiting);
        assert_eq!(call.poll(10, &mut send), CallProgress::Unknown);
        assert_eq!(call.request_id(), Some(4));
        let mut malformed = PendingCall::new(
            DisplayRequest::Remove(reference()),
            "remove.44".into(),
            None,
            100,
            0,
        )
        .unwrap();
        let mut replies = VecDeque::from([
            Ok(Response::Accepted { id: 8 }),
            Ok(response(json!({"ok":true}))),
            Ok(Response::Ok),
        ]);
        let mut send = |_: Command| replies.pop_front().unwrap();
        assert_eq!(malformed.poll(1, &mut send), CallProgress::Waiting);
        assert_eq!(malformed.poll(2, &mut send), CallProgress::Waiting);
        assert_eq!(malformed.poll(3, &mut send), CallProgress::Unknown);
    }

    #[test]
    fn invalid_requests_fail_before_transport() {
        let mut request = create();
        request.scale = Some(123);
        assert!(
            PendingCall::new(
                DisplayRequest::Create(request),
                "create.1".into(),
                None,
                5000,
                0
            )
            .is_err()
        );
        let mut supported = create();
        supported.scale = Some(-1);
        assert!(
            PendingCall::new(
                DisplayRequest::Create(supported),
                "create.2".into(),
                None,
                5000,
                0
            )
            .is_ok()
        );
        let mut reference = reference();
        reference.reference_id = "with space".into();
        assert!(
            PendingCall::new(
                DisplayRequest::Status(reference),
                "status.1".into(),
                None,
                5000,
                0
            )
            .is_err()
        );
        assert!(
            PendingCall::new(
                DisplayRequest::Status(super::tests::reference()),
                "BAD".into(),
                None,
                5000,
                0
            )
            .is_err()
        );
    }
    #[test]
    fn reconfiguration_requires_exact_operation_echo_and_known_state() {
        let request = DisplayRequest::Reconfigure {
            reference: reference(),
            operation_id: "resize.abc".into(),
            borrow_id: "a".repeat(64),
            width: 1280,
            height: 720,
            refresh_millihz: 60000,
            domain_id: "provider_session:abc".into(),
            revision: 3,
        };
        let pending = json!({"ok":true,"state":"pending","operation_id":"resize.abc"});
        assert_eq!(
            parse_response(&request, &pending),
            Some(DisplayOutcome::ReconfigurePending)
        );
        let mut changed = pending.clone();
        changed["operation_id"] = json!("resize.other");
        assert!(parse_response(&request, &changed).is_none());
        changed = pending;
        changed["state"] = json!("unknown");
        assert!(parse_response(&request, &changed).is_none());
        let mut call = PendingCall::new(request, "transport.1".into(), Some(77), 5000, 0).unwrap();
        assert_eq!(
            call.poll(1, &mut |command| match command {
                Command::Request {
                    payload, parent, ..
                } => {
                    assert_eq!(parent, Some(77));
                    assert_eq!(payload["expected_topology_revision"], 3);
                    assert_eq!(payload["operation_id"], "resize.abc");
                    Ok(Response::Accepted { id: 1 })
                }
                _ => panic!("unexpected command"),
            }),
            CallProgress::Waiting
        );
    }
    #[test]
    fn recovery_status_is_lookup_only_and_rejects_wrong_operation() {
        let request = DisplayRequest::ReconfigureStatus {
            reference: reference(),
            operation_id: "resize.abc".into(),
            borrow_id: "a".repeat(64),
            domain_id: "provider_session:abc".into(),
            revision: 3,
        };
        let payload = request.payload().unwrap();
        assert_eq!(payload["action"], "reconfigure_status");
        assert_eq!(payload["operation_id"], "resize.abc");
        assert!(payload.get("width").is_none());
        assert_eq!(
            parse_response(
                &request,
                &json!({"ok":true,"state":"pending","operation_id":"resize.abc"})
            ),
            Some(DisplayOutcome::ReconfigurePending)
        );
        assert!(
            parse_response(
                &request,
                &json!({"ok":true,"state":"pending","operation_id":"resize.other"})
            )
            .is_none()
        );
        assert!(matches!(
            parse_response(&request, &json!({"ok":false,"code":"recovery_required"})),
            Some(DisplayOutcome::ProviderError(_))
        ));
    }
}
