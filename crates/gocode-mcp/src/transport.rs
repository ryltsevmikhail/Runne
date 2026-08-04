use gocode_tools::{
    EffectAdmission, ToolDispatchRequest, ToolExecutionHandle, ToolProtocolCloseRequest,
};
use serde_json::Value;

use crate::{McpNormalizedMessage, McpRequestId};

/// Trusted byte and semantic limits for one MCP generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpTransportLimits {
    /// Maximum bytes in one frame.
    pub max_frame_bytes: usize,
    /// Maximum cumulative bytes per owner-reset window.
    pub max_buffer_bytes: usize,
    /// Maximum JSON nesting.
    pub max_nesting: usize,
    /// Maximum entries in any array/object.
    pub max_collection_items: usize,
    /// Maximum bytes in one string/key.
    pub max_string_bytes: usize,
    /// Maximum concurrent requests.
    pub max_in_flight: usize,
    /// Maximum concurrent notifications awaiting owner acknowledgement.
    pub max_in_flight_notifications: usize,
    /// Maximum frames per owner-reset window.
    pub max_frames_per_window: usize,
}

impl Default for McpTransportLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            max_buffer_bytes: 4 * 1024 * 1024,
            max_nesting: 32,
            max_collection_items: 4096,
            max_string_bytes: 256 * 1024,
            max_in_flight: 64,
            max_in_flight_notifications: 256,
            max_frames_per_window: 1024,
        }
    }
}

/// Sensitivity-safe transport rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTransportError {
    /// Byte/frame/buffer bound exceeded.
    ByteLimit,
    /// JSON semantic bound exceeded.
    SemanticLimit,
    /// JSON-RPC shape malformed.
    MalformedMessage,
    /// Protocol is not exact JSON-RPC 2.0.
    UnsupportedProtocol,
    /// In-flight admission exhausted.
    InFlightLimit,
    /// Rate admission exhausted.
    RateLimit,
    /// Project-owned bridge unavailable.
    Unavailable,
}

/// Already-owned local or broker transport.
pub trait McpTransportPort {
    /// Sends one bounded frame.
    fn send(&mut self, frame: &[u8]) -> Result<(), McpTransportError>;
    /// Receives into caller-owned bounded memory.
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, McpTransportError>;
}

/// Stable project-owned client adapter port.
pub trait McpClientPort {
    /// Dispatches one normalized request under external authority.
    fn dispatch(&mut self, message: &McpNormalizedMessage) -> Result<(), McpTransportError>;
    /// Receives one normalized message.
    fn receive(&mut self) -> Result<McpNormalizedMessage, McpTransportError>;
}

/// Client-owned confirmation boundary for correlated protocol completion.
pub trait McpProtocolCompletionPort {
    /// Reserves one exact admission before client dispatch reaches its effect boundary.
    fn reserve_protocol_completion(
        &mut self,
        request: &ToolDispatchRequest,
        admission: &EffectAdmission,
        handle: &ToolExecutionHandle,
    ) -> Result<(), McpTransportError>;
    /// Confirms a privately recorded terminal claim and settles it once.
    fn confirm_protocol_completion(
        &mut self,
        request: &ToolProtocolCloseRequest,
    ) -> Result<(), McpTransportError>;
}

/// Pre-decode bounded MCP transport admission.
pub struct BoundedMcpTransport<P> {
    port: P,
    limits: McpTransportLimits,
    admitted_bytes: usize,
    frames: usize,
    in_flight: usize,
    in_flight_notifications: usize,
}

impl<P> BoundedMcpTransport<P> {
    /// Wraps an already-owned bridge.
    pub const fn new(port: P, limits: McpTransportLimits) -> Self {
        Self {
            port,
            limits,
            admitted_bytes: 0,
            frames: 0,
            in_flight: 0,
            in_flight_notifications: 0,
        }
    }
    /// Resets owner-controlled byte/rate window counters.
    pub fn reset_admission_window(&mut self) {
        self.admitted_bytes = 0;
        self.frames = 0;
    }
    /// Claims one request slot.
    pub fn claim_request(&mut self) -> Result<(), McpTransportError> {
        if self.in_flight >= self.limits.max_in_flight {
            return Err(McpTransportError::InFlightLimit);
        }
        self.in_flight += 1;
        Ok(())
    }
    /// Releases one request slot after a project terminal outcome.
    pub fn complete_request(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }
    /// Claims one notification slot.
    pub fn claim_notification(&mut self) -> Result<(), McpTransportError> {
        if self.in_flight_notifications >= self.limits.max_in_flight_notifications {
            return Err(McpTransportError::InFlightLimit);
        }
        self.in_flight_notifications += 1;
        Ok(())
    }
    /// Releases one notification slot after owner acknowledgement.
    pub fn complete_notification(&mut self) {
        self.in_flight_notifications = self.in_flight_notifications.saturating_sub(1);
    }
    /// Decodes one already-captured bounded frame.
    pub fn decode_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<McpNormalizedMessage, McpTransportError> {
        self.admit(frame.len())?;
        let value: Value =
            serde_json::from_slice(frame).map_err(|_| McpTransportError::MalformedMessage)?;
        validate_value(&value, &self.limits, 0)?;
        normalize(value)
    }
    fn admit(&mut self, bytes: usize) -> Result<(), McpTransportError> {
        if bytes == 0 || bytes > self.limits.max_frame_bytes {
            return Err(McpTransportError::ByteLimit);
        }
        let total = self
            .admitted_bytes
            .checked_add(bytes)
            .ok_or(McpTransportError::ByteLimit)?;
        if total > self.limits.max_buffer_bytes {
            return Err(McpTransportError::ByteLimit);
        }
        if self.frames >= self.limits.max_frames_per_window {
            return Err(McpTransportError::RateLimit);
        }
        self.admitted_bytes = total;
        self.frames += 1;
        Ok(())
    }
}

impl<P: McpTransportPort> BoundedMcpTransport<P> {
    /// Receives into exact trusted preallocated memory.
    pub fn receive_message(&mut self) -> Result<McpNormalizedMessage, McpTransportError> {
        let mut buffer = vec![0; self.limits.max_frame_bytes];
        let size = self.port.receive(&mut buffer)?;
        if size > buffer.len() {
            return Err(McpTransportError::ByteLimit);
        }
        self.decode_frame(&buffer[..size])
    }
    /// Sends one exact bounded frame.
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), McpTransportError> {
        self.admit(frame.len())?;
        self.port.send(frame)
    }
}

fn validate_value(
    value: &Value,
    limits: &McpTransportLimits,
    depth: usize,
) -> Result<(), McpTransportError> {
    if depth > limits.max_nesting {
        return Err(McpTransportError::SemanticLimit);
    }
    match value {
        Value::String(value) if value.len() > limits.max_string_bytes => {
            Err(McpTransportError::SemanticLimit)
        }
        Value::Array(values) => {
            if values.len() > limits.max_collection_items {
                return Err(McpTransportError::SemanticLimit);
            }
            for value in values {
                validate_value(value, limits, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > limits.max_collection_items
                || values.keys().any(|key| key.len() > limits.max_string_bytes)
            {
                return Err(McpTransportError::SemanticLimit);
            }
            for value in values.values() {
                validate_value(value, limits, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn normalize(value: Value) -> Result<McpNormalizedMessage, McpTransportError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or(McpTransportError::MalformedMessage)?;
    if object.remove("jsonrpc") != Some(Value::String("2.0".to_owned())) {
        return Err(McpTransportError::UnsupportedProtocol);
    }
    let request_id = object.remove("id").map(parse_id).transpose()?;
    let method = object
        .remove("method")
        .map(|value| match value {
            Value::String(value) if !value.is_empty() => Ok(value),
            _ => Err(McpTransportError::MalformedMessage),
        })
        .transpose()?;
    let params = object.remove("params");
    let result = object.remove("result");
    let error_code = object
        .remove("error")
        .map(|value| {
            let object = value
                .as_object()
                .ok_or(McpTransportError::MalformedMessage)?;
            if !matches!(object.get("message"), Some(Value::String(_))) {
                return Err(McpTransportError::MalformedMessage);
            }
            object
                .get("code")
                .and_then(Value::as_i64)
                .ok_or(McpTransportError::MalformedMessage)
        })
        .transpose()?;
    if !object.is_empty()
        || (method.is_some() && (result.is_some() || error_code.is_some()))
        || (method.is_none() && (request_id.is_none() || result.is_some() == error_code.is_some()))
    {
        return Err(McpTransportError::MalformedMessage);
    }
    Ok(McpNormalizedMessage {
        request_id,
        method,
        params,
        result,
        error_code,
    })
}

fn parse_id(value: Value) -> Result<McpRequestId, McpTransportError> {
    match value {
        Value::Number(value) => value
            .as_u64()
            .map(McpRequestId::Number)
            .ok_or(McpTransportError::MalformedMessage),
        Value::String(value) if !value.is_empty() && value.len() <= 128 => {
            Ok(McpRequestId::String(value))
        }
        _ => Err(McpTransportError::MalformedMessage),
    }
}
