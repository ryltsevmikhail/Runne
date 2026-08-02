use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, RwLock, RwLockReadGuard, TryLockError},
};

use gocode_tools::{
    EffectAdmission, InvalidToolDefinition, SandboxProfile, ToolAdmissionPort, ToolClass,
    ToolDefinition, ToolDispatchBinding, ToolDispatchRequest, ToolExecutionHandle,
    ToolExecutorError, ToolExecutorPort, ToolGateway, ToolGatewayError, ToolId, ToolOutputBounds,
    ToolRef, ToolRegistry, ToolRegistryError, ToolVersion, ToolsetSnapshot,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    InvalidMcpIdentity, McpClientPort, McpConnectionId, McpInvocationId, McpNormalizedMessage,
    McpRequestId, McpRuntimeInstanceId, McpServerId, McpSessionId,
};

const MAX_MCP_TOOL_DESCRIPTORS: usize = 4096;
const MAX_MCP_TOOL_NAME_BYTES: usize = 128;
const MCP_TOOLS_CALL_METHOD: &str = "tools/call";
const MCP_REQUEST_CLASS: &[u8] = b"request";

/// MCP server containment class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpServerKind {
    /// Contained local server process.
    Local,
    /// Brokered remote server.
    Remote,
}

/// One bounded normalized MCP tool descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct McpToolDescriptor {
    name: String,
    version: ToolVersion,
    input_schema: Value,
}

impl McpToolDescriptor {
    /// Captures a normalized descriptor.
    pub fn new(
        name: impl Into<String>,
        version: &str,
        input_schema: Value,
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
        })
    }

    /// Server-local tool name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Complete normalized discovery snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct McpDiscoverySnapshot {
    server_id: McpServerId,
    tools: Box<[McpToolDescriptor]>,
    digest: [u8; 32],
}

impl McpDiscoverySnapshot {
    /// Freezes one complete canonical descriptor set.
    pub fn new(
        server_id: McpServerId,
        mut tools: Vec<McpToolDescriptor>,
    ) -> Result<Self, McpDiscoveryError> {
        if tools.len() > MAX_MCP_TOOL_DESCRIPTORS {
            return Err(McpDiscoveryError::TooManyDefinitions);
        }
        tools.sort_by(|left, right| (&left.name, left.version).cmp(&(&right.name, right.version)));
        if tools
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name && pair[0].version == pair[1].version)
        {
            return Err(McpDiscoveryError::DuplicateDefinition);
        }
        let digest = discovery_digest(&server_id, &tools);
        Ok(Self {
            server_id,
            tools: tools.into_boxed_slice(),
            digest,
        })
    }

    /// Canonically ordered tools.
    pub fn tools(&self) -> &[McpToolDescriptor] {
        &self.tools
    }

    /// Complete snapshot digest.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Discovery normalization/publication failure.
#[derive(Debug, PartialEq, Eq)]
pub enum McpDiscoveryError {
    /// Identifier or exact version was invalid.
    InvalidIdentity,
    /// Descriptor bound was exceeded.
    TooManyDefinitions,
    /// Same exact descriptor occurred twice.
    DuplicateDefinition,
    /// Schema validation failed.
    InvalidDefinition(InvalidToolDefinition),
    /// Atomic registry publication failed.
    Registry(ToolRegistryError),
}

/// Immutable allowlist-filtered MCP tool publication.
pub struct PublishedMcpTools {
    server_id: McpServerId,
    registry: ToolRegistry,
    snapshot: ToolsetSnapshot,
    discovery_digest: [u8; 32],
    server_names: BTreeMap<ToolRef, String>,
}

impl PublishedMcpTools {
    /// Exact published refs after allowlist filtering.
    pub const fn snapshot(&self) -> &ToolsetSnapshot {
        &self.snapshot
    }

    /// Resolves only an exact published definition.
    pub fn resolve(&self, tool_ref: &ToolRef) -> Result<&ToolDefinition, McpDiscoveryError> {
        self.registry
            .resolve(tool_ref)
            .map_err(McpDiscoveryError::Registry)
    }

    /// Complete pre-filter discovery digest carried into dispatch authority.
    pub const fn discovery_digest(&self) -> &[u8; 32] {
        &self.discovery_digest
    }

    /// Issues one opaque, single-use capability for an exact published tool,
    /// invocation, request body and generation-bound connection.
    pub fn issue_dispatch(
        &self,
        binding: &McpDispatchBinding,
        tool_ref: &ToolRef,
        invocation_id: McpInvocationId,
        input: Value,
    ) -> Result<McpToolDispatchCapability, McpDispatchCapabilityError> {
        if binding.server_id != self.server_id || binding.discovery_digest != self.discovery_digest
        {
            return Err(McpDispatchCapabilityError::InvalidBinding);
        }
        let definition = self
            .resolve(tool_ref)
            .map_err(|_| McpDispatchCapabilityError::ToolNotPublished)?;
        if !matches!(
            definition.class(),
            ToolClass::McpLocal | ToolClass::McpRemote
        ) {
            return Err(McpDispatchCapabilityError::ToolNotPublished);
        }
        let server_tool_name = self
            .server_names
            .get(tool_ref)
            .cloned()
            .ok_or(McpDispatchCapabilityError::ToolNotPublished)?;
        self.registry
            .validate_input(tool_ref, &input)
            .map_err(McpDispatchCapabilityError::InvalidInput)?;
        let request_digest = call_digest(binding, tool_ref, &invocation_id, &input);
        Ok(McpToolDispatchCapability {
            binding: binding.clone(),
            tool_ref: tool_ref.clone(),
            invocation_id,
            input,
            server_tool_name,
            request_digest,
        })
    }
}

/// Failure to mint exact MCP dispatch authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpDispatchCapabilityError {
    /// Binding does not belong to this exact server/discovery snapshot.
    InvalidBinding,
    /// Tool was excluded or absent from the immutable publication.
    ToolNotPublished,
    /// Input does not satisfy the exact published schema.
    InvalidInput(ToolRegistryError),
}

/// Opaque single-use authority for one exact MCP tool call.
pub struct McpToolDispatchCapability {
    binding: McpDispatchBinding,
    tool_ref: ToolRef,
    invocation_id: McpInvocationId,
    input: Value,
    server_tool_name: String,
    request_digest: [u8; 32],
}

/// Normalizes, filters and atomically publishes an exact MCP tool snapshot.
pub fn publish_mcp_tools(
    server_id: McpServerId,
    kind: McpServerKind,
    descriptors: Vec<McpToolDescriptor>,
    allowlist: &[&str],
) -> Result<PublishedMcpTools, McpDiscoveryError> {
    let snapshot = McpDiscoverySnapshot::new(server_id.clone(), descriptors)?;
    let allowed = allowlist.iter().copied().collect::<BTreeSet<_>>();
    let mut definitions = Vec::new();
    let mut server_names = BTreeMap::new();
    for descriptor in snapshot.tools() {
        if !allowed.contains(descriptor.name()) {
            continue;
        }
        let tool_id = ToolId::new(format!("mcp::{}::{}", server_id.as_str(), descriptor.name))
            .map_err(|_| McpDiscoveryError::InvalidIdentity)?;
        let tool_ref = ToolRef::new(tool_id.clone(), descriptor.version);
        let definition = ToolDefinition::new(
            tool_id,
            descriptor.version,
            match kind {
                McpServerKind::Local => ToolClass::McpLocal,
                McpServerKind::Remote => ToolClass::McpRemote,
            },
            descriptor.input_schema.clone(),
            match kind {
                McpServerKind::Local => SandboxProfile::McpLocal,
                McpServerKind::Remote => SandboxProfile::NetworkRestricted,
            },
        )
        .map_err(McpDiscoveryError::InvalidDefinition)?;
        server_names.insert(tool_ref, descriptor.name.clone());
        definitions.push(definition);
    }
    let mut registry = ToolRegistry::new();
    let toolset = registry
        .register_batch_snapshot_exact(definitions)
        .map_err(McpDiscoveryError::Registry)?;
    Ok(PublishedMcpTools {
        server_id,
        registry,
        snapshot: toolset,
        discovery_digest: *snapshot.digest(),
        server_names,
    })
}
