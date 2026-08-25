use runne_app_core::CanonicalId;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Runtime};

const PREFIX: &str = "runne://open?";
const MAX_ACTIVATION_BYTES: usize = 2048;
#[cfg_attr(test, allow(dead_code))]
pub const EVENT_NAME: &str = "runne://external-activation";

/// Buffers the latest validated activation so startup delivery cannot race
/// the renderer listener. A second-instance event is also emitted live.
#[cfg_attr(test, allow(dead_code))]
#[derive(Clone, Default)]
pub struct ActivationManager {
    pending: Arc<Mutex<Option<ActivationTarget>>>,
}

#[cfg_attr(test, allow(dead_code))]
impl ActivationManager {
    pub fn forward<I, S, R>(&self, app: &AppHandle<R>, args: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
        R: Runtime,
    {
        let Some(target) = args.into_iter().find_map(|argument| {
            argument
                .as_ref()
                .to_str()
                .and_then(|value| parse_activation(value).ok())
        }) else {
            return;
        };
        if let Ok(mut pending) = self.pending.lock() {
            *pending = Some(target.clone());
        }
        let _ = app.emit(EVENT_NAME, target);
    }

    pub fn take(&self) -> Option<ActivationTarget> {
        self.pending
            .lock()
            .ok()
            .and_then(|mut pending| pending.take())
    }
}

/// A renderer-safe route request. It contains no URL, credential, authority,
/// or executable data; the host must still reconcile each identity before
/// navigation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivationTarget {
    pub runtime: Option<String>,
    pub project_id: Option<String>,
    pub workspace_id: Option<String>,
    pub task_run_id: Option<String>,
    pub approval_id: Option<String>,
    pub event: Option<ActivationEvent>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationEvent {
    Approval,
    TaskCompleted,
    RuntimeAttention,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    InvalidShape,
    InvalidEncoding,
    UnknownParameter,
    DuplicateParameter,
    InvalidValue,
}

/// Parses one allowlisted external activation into route data.
///
/// Percent encoding is accepted only for UTF-8 values and is decoded before
/// validation. The resulting object is deliberately not an authorization
/// capability; callers must fetch current runtime state before routing.
pub fn parse_activation(value: &str) -> Result<ActivationTarget, ActivationError> {
    if value.len() > MAX_ACTIVATION_BYTES
        || !value.starts_with(PREFIX)
        || value.contains('#')
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(ActivationError::InvalidShape);
    }

    let mut target = ActivationTarget {
        runtime: None,
        project_id: None,
        workspace_id: None,
        task_run_id: None,
        approval_id: None,
        event: None,
    };
    let mut version = None;
    for pair in value[PREFIX.len()..].split('&') {
        let (raw_key, raw_value) = pair.split_once('=').ok_or(ActivationError::InvalidShape)?;
        let key = decode(raw_key)?;
        let decoded = decode(raw_value)?;
        if decoded.is_empty() || !is_ascii_key(&key) {
            return Err(ActivationError::InvalidValue);
        }
        match key.as_str() {
            "v" => set_once(&mut version, decoded)?,
            "runtime" => set_once(&mut target.runtime, decoded)?,
            "project" => set_id(&mut target.project_id, decoded)?,
            "workspace" => set_id(&mut target.workspace_id, decoded)?,
            "taskrun" => set_id(&mut target.task_run_id, decoded)?,
            "approval" => set_id(&mut target.approval_id, decoded)?,
            "event" => set_once(&mut target.event, parse_event(&decoded)?)?,
            _ => return Err(ActivationError::UnknownParameter),
        }
    }
    if version.as_deref() != Some("1")
        || target
            .runtime
            .as_ref()
            .is_some_and(|value| !valid_runtime(value))
        || (target.project_id.is_none()
            && target.workspace_id.is_none()
            && target.task_run_id.is_none()
            && target.approval_id.is_none())
    {
        return Err(ActivationError::InvalidValue);
    }
    Ok(target)
}

fn decode(value: &str) -> Result<String, ActivationError> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut chars = value.as_bytes().iter().copied();
    while let Some(byte) = chars.next() {
        match byte {
            b'%' => {
                let high = chars.next().ok_or(ActivationError::InvalidEncoding)?;
                let low = chars.next().ok_or(ActivationError::InvalidEncoding)?;
                bytes.push((hex(high)? << 4) | hex(low)?);
            }
            b'+' => bytes.push(b' '),
            byte if byte.is_ascii() && !byte.is_ascii_control() => bytes.push(byte),
            _ => return Err(ActivationError::InvalidEncoding),
        }
    }
    String::from_utf8(bytes).map_err(|_| ActivationError::InvalidEncoding)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), ActivationError> {
    if slot.replace(value).is_some() {
        return Err(ActivationError::DuplicateParameter);
    }
    Ok(())
}

fn set_id(slot: &mut Option<String>, value: String) -> Result<(), ActivationError> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ActivationError::InvalidValue);
    }
    CanonicalId::parse(&value).map_err(|_| ActivationError::InvalidValue)?;
    set_once(slot, value)
}

fn parse_event(value: &str) -> Result<ActivationEvent, ActivationError> {
    match value {
        "approval" => Ok(ActivationEvent::Approval),
        "task_completed" => Ok(ActivationEvent::TaskCompleted),
        "runtime_attention" => Ok(ActivationEvent::RuntimeAttention),
        _ => Err(ActivationError::InvalidValue),
    }
}

fn valid_runtime(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        && !value.contains("..")
        && !value.starts_with('/')
        && !value.ends_with('/')
}

fn is_ascii_key(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii())
}

const fn hex(value: u8) -> Result<u8, ActivationError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ActivationError::InvalidEncoding),
    }
}
