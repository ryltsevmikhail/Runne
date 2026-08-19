use runne_tools::{ProcessIntentDigestV1, ToolRef, ToolVersion};
use serde_json::Value;

use super::{McpDiscoveryError, McpDispatchBinding, McpInvocationId};

const MAX_MCP_TOOL_NAME_BYTES: usize = 128;

/// Execution path selected for a discovered MCP tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpToolExecutionClass {
    /// Existing fixture protocol flow.
    ProtocolOnly,
    /// Task 6 process-contract flow.
    ProcessBacked,
}

impl McpToolExecutionClass {
    pub(super) const fn label(self) -> &'static [u8] {
        match self {
            Self::ProtocolOnly => b"protocol-only",
            Self::ProcessBacked => b"process-backed",
        }
    }
}

/// One bounded normalized MCP tool descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct McpToolDescriptor {
    pub(super) name: String,
    pub(super) version: ToolVersion,
    pub(super) input_schema: Value,
    execution_class: McpToolExecutionClass,
}

impl McpToolDescriptor {
    /// Captures a normalized descriptor for the existing protocol-only flow.
    pub fn new(
        name: impl Into<String>,
        version: &str,
        input_schema: Value,
    ) -> Result<Self, McpDiscoveryError> {
        Self::new_with_execution_class(
            name,
            version,
            input_schema,
            McpToolExecutionClass::ProtocolOnly,
        )
    }

    /// Captures a normalized descriptor with an explicit execution class.
    pub fn new_with_execution_class(
        name: impl Into<String>,
        version: &str,
        input_schema: Value,
        execution_class: McpToolExecutionClass,
    ) -> Result<Self, McpDiscoveryError> {
        let name = name.into();
        if name.is_empty()
            || name.len() > MAX_MCP_TOOL_NAME_BYTES
            || name.contains("::")
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(McpDiscoveryError::InvalidIdentity);
        }
        Ok(Self {
            name,
            version: ToolVersion::new(version).map_err(|_| McpDiscoveryError::InvalidIdentity)?,
            input_schema,
            execution_class,
        })
    }

    /// Server-local tool name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Required execution path for this descriptor.
    pub const fn execution_class(&self) -> McpToolExecutionClass {
        self.execution_class
    }
}

/// Failure to mint exact MCP dispatch authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpDispatchCapabilityError {
    /// Binding does not belong to this exact server/discovery snapshot.
    InvalidBinding,
    /// Tool was excluded, absent, or does not match the requested issuance path.
    ToolNotPublished,
    /// Typed process issuance targeted a protocol-only tool.
    ExecutionClassMismatch,
    /// A process-backed tool requires an exact process intent digest.
    ProcessIntentRequired,
    /// Input does not satisfy the exact published schema.
    InvalidInput(runne_tools::ToolRegistryError),
}

/// Opaque single-use authority for one exact MCP tool call.
pub struct McpToolDispatchCapability {
    pub(super) binding: McpDispatchBinding,
    pub(super) tool_ref: ToolRef,
    pub(super) invocation_id: McpInvocationId,
    pub(super) input: Value,
    pub(super) server_tool_name: String,
    pub(super) request_digest: [u8; 32],
    pub(super) execution_class: McpToolExecutionClass,
    pub(super) process_intent_digest: Option<ProcessIntentDigestV1>,
}

impl McpToolDispatchCapability {
    /// Execution class selected by the immutable descriptor publication.
    pub const fn execution_class(&self) -> McpToolExecutionClass {
        self.execution_class
    }

    pub(crate) const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
}
