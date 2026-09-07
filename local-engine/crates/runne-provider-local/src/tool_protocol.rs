//! `structured-tools-v1` protocol contract (Plan Task 11): the
//! manifest-qualified rendering/parser shape for tool proposals.
//! Declared tools render deterministically into the prompt block;
//! model proposals normalize into an EXISTING provider tool event.
//! Execution lives exclusively in the ToolGateway — nothing in this
//! module can invoke a tool.

use crate::error::ProviderError;
use serde_json::Value;

pub const TOOLS_PROTOCOL_ID: &str = "structured-tools-v1";

/// Bounded proposal shape (PROTOCOL: tool_call_id, declared name,
/// bounded JSON args).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallProposal {
    pub tool_call_id: String,
    pub name: String,
    /// Canonical JSON text of the arguments object.
    pub args_json: String,
}

pub const MAX_NAME_BYTES: usize = 128;
pub const MAX_ARGS_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolProtocolError {
    /// The manifest did not qualify `tools`; proposals are out of
    /// contract entirely.
    NotQualified,
    Malformed,
    OverLimitArgs,
    OverLimitName,
}

impl From<ToolProtocolError> for ProviderError {
    fn from(e: ToolProtocolError) -> Self {
        ProviderError::ToolProtocol(e)
    }
}

impl std::fmt::Display for ToolProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotQualified => write!(f, "tools not qualified by manifest"),
            Self::Malformed => write!(f, "malformed tool proposal"),
            Self::OverLimitArgs => write!(f, "tool args over bounded limit"),
            Self::OverLimitName => write!(f, "tool name over bounded limit"),
        }
    }
}

/// One declared tool from the admitted manifest (name + bounded JSON
/// schema text). Rendering is deterministic: declared order, sorted
/// schema keys via canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDeclaration {
    pub name: String,
    pub description: String,
    pub schema_json: String,
}

/// Renders the tools declaration block for the prompt. Deterministic:
/// same declarations → same bytes. Empty list → empty block (tools
/// disabled on the wire).
pub fn render_tools_declaration(tools: &[ToolDeclaration]) -> Result<String, ToolProtocolError> {
    if tools.is_empty() {
        return Ok(String::new());
    }
    let mut out = String::from("# Tools\nRespond with a tool_proposal item:\n");
    for t in tools {
        if t.name.len() > MAX_NAME_BYTES {
            return Err(ToolProtocolError::OverLimitName);
        }
        out.push_str(&format!(
            "- {}({}): {}",
            t.name,
            canonical_args_schema(&t.schema_json)?,
            t.description
        ));
        out.push('\n');
    }
    Ok(out)
}

fn canonical_args_schema(schema_json: &str) -> Result<String, ToolProtocolError> {
    let v: Value = serde_json::from_str(schema_json).map_err(|_| ToolProtocolError::Malformed)?;
    serde_json_canonicalizer::to_string(&v).map_err(|_| ToolProtocolError::Malformed)
}

/// Derives the deterministic `tool_call_id` for a proposal: bound to
/// the stream sequence so replay yields the same id (LOCAL-INV-002).
pub fn derive_tool_call_id(stream_id: &[u8; 16], stream_sequence: u64) -> String {
    let mut id = String::with_capacity(32 + 4);
    for b in stream_id.iter() {
        id.push_str(&format!("{b:02x}"));
    }
    id.push_str(&format!("-{stream_sequence:04x}"));
    id
}
