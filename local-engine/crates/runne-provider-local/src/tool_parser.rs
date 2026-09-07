//! Tool proposal parser (Plan Task 11): normalizes a model tool
//! proposal from the stream into the existing normalized provider tool
//! event shape. The parser NEVER executes: its only output is a
//! bounded proposal handed to the ToolGateway's ordered gates.

use crate::error::ProviderError;
use crate::tool_protocol::{
    MAX_ARGS_BYTES, MAX_NAME_BYTES, ToolProtocolError, derive_tool_call_id,
};
use serde_json::Value;

/// A parsed, bounded, idempotent tool event (the provider-normalized
/// shape; the product `ToolCallRequested` carries the same fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedToolEvent {
    pub tool_call_id: String,
    pub name: String,
    pub args_json: String,
}

/// Whether the admitted manifest qualified tool proposals at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolParser {
    qualified: bool,
}

impl ToolParser {
    /// `capabilities.tools` from the admitted manifest decides.
    pub fn from_capabilities(tools_qualified: bool) -> Self {
        Self {
            qualified: tools_qualified,
        }
    }

    /// Normalizes one stream item. `Ok(None)` for non-tool kinds
    /// (text/usage/finish continue the stream untouched). A tool
    /// proposal without manifest qualification is out of contract and
    /// rejects the stream — the model cannot opt in by itself.
    pub fn normalize(
        &self,
        kind: &str,
        stream_id: &[u8; 16],
        stream_sequence: u64,
        payload: &[u8],
    ) -> Result<Option<NormalizedToolEvent>, ProviderError> {
        if kind != "tool_proposal" {
            return Ok(None);
        }
        if !self.qualified {
            return Err(ProviderError::ToolProtocol(ToolProtocolError::NotQualified));
        }
        let value: Value = serde_json::from_slice(payload)
            .map_err(|_| ProviderError::ToolProtocol(ToolProtocolError::Malformed))?;
        let Value::Object(map) = &value else {
            return Err(ProviderError::ToolProtocol(ToolProtocolError::Malformed));
        };
        let name = match map.get("name") {
            Some(Value::String(n)) if !n.is_empty() => n.clone(),
            _ => return Err(ProviderError::ToolProtocol(ToolProtocolError::Malformed)),
        };
        if name.len() > MAX_NAME_BYTES {
            return Err(ProviderError::ToolProtocol(
                ToolProtocolError::OverLimitName,
            ));
        }
        let args = map
            .get("args")
            .cloned()
            .unwrap_or(Value::Object(Default::default()));
        let args_json = serde_json_canonicalizer::to_string(&args)
            .map_err(|_| ProviderError::ToolProtocol(ToolProtocolError::Malformed))?;
        if args_json.len() > MAX_ARGS_BYTES {
            return Err(ProviderError::ToolProtocol(
                ToolProtocolError::OverLimitArgs,
            ));
        }
        Ok(Some(NormalizedToolEvent {
            tool_call_id: derive_tool_call_id(stream_id, stream_sequence),
            name,
            args_json,
        }))
    }
}
