use crate::{
    InvalidMcpIdentity, McpClientPort, McpConnectionId, McpInvocationId, McpNormalizedMessage,
    McpProtocolCompletionPort, McpRequestId, McpRuntimeInstanceId, McpServerId, McpSessionId,
};
use gocode_tools::{
    EffectAdmission, InvalidToolDefinition, SandboxProfile, ToolAdmissionPort, ToolClass,
    ToolDefinition, ToolDispatchBinding, ToolDispatchRequest, ToolExecutionHandle,
    ToolExecutorError, ToolExecutorPort, ToolGateway, ToolGatewayError, ToolId, ToolOutputBounds,
    ToolProtocolCloseRequest, ToolRef, ToolRegistry, ToolRegistryError, ToolTerminalDisposition,
    ToolsetSnapshot,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError},
};
const MAX_MCP_TOOL_DESCRIPTORS: usize = 4096;
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
        kind: McpServerKind,
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
        let digest = discovery_digest(&server_id, kind, &tools);
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
    kind: McpServerKind,
    registry: ToolRegistry,
    snapshot: ToolsetSnapshot,
    discovery_digest: [u8; 32],
    server_names: BTreeMap<ToolRef, String>,
    execution_classes: BTreeMap<ToolRef, McpToolExecutionClass>,
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
}

/// Normalizes, filters and atomically publishes an exact MCP tool snapshot.
pub fn publish_mcp_tools(
    server_id: McpServerId,
    kind: McpServerKind,
    descriptors: Vec<McpToolDescriptor>,
    allowlist: &[&str],
) -> Result<PublishedMcpTools, McpDiscoveryError> {
    let snapshot = McpDiscoverySnapshot::new(server_id.clone(), kind, descriptors)?;
    let allowed = allowlist.iter().copied().collect::<BTreeSet<_>>();
    let mut definitions = Vec::new();
    let mut server_names = BTreeMap::new();
    let mut execution_classes = BTreeMap::new();
    for descriptor in snapshot.tools() {
        if !allowed.contains(descriptor.name()) {
            continue;
        }
        let tool_id = ToolId::new(format!("mcp::{}::{}", server_id.as_str(), descriptor.name))
            .map_err(|_| McpDiscoveryError::InvalidIdentity)?;
        let tool_ref = ToolRef::new(tool_id.clone(), descriptor.version);
        let mapping = publication_mapping(kind, descriptor.execution_class());
        let definition = ToolDefinition::new(
            tool_id,
            descriptor.version,
            mapping.class,
            descriptor.input_schema.clone(),
            mapping.sandbox,
        )
        .map_err(McpDiscoveryError::InvalidDefinition)?;
        execution_classes.insert(tool_ref.clone(), descriptor.execution_class());
        server_names.insert(tool_ref, descriptor.name.clone());
        definitions.push(definition);
    }
    let mut registry = ToolRegistry::new();
    let toolset = registry
        .register_batch_snapshot_exact(definitions)
        .map_err(McpDiscoveryError::Registry)?;
    Ok(PublishedMcpTools {
        server_id,
        kind,
        registry,
        snapshot: toolset,
        discovery_digest: *snapshot.digest(),
        server_names,
        execution_classes,
    })
}

struct PublicationMapping {
    class: ToolClass,
    sandbox: SandboxProfile,
}

#[rustfmt::skip]
fn publication_mapping(kind: McpServerKind, execution_class: McpToolExecutionClass) -> PublicationMapping {
    match (execution_class, kind) {
        (McpToolExecutionClass::ProtocolOnly, McpServerKind::Local) => PublicationMapping {
            class: ToolClass::McpLocal,
            sandbox: SandboxProfile::McpLocal,
        },
        (McpToolExecutionClass::ProtocolOnly, McpServerKind::Remote) => PublicationMapping {
            class: ToolClass::McpRemote,
            sandbox: SandboxProfile::NetworkRestricted,
        },
        (McpToolExecutionClass::ProcessBacked, McpServerKind::Local) => PublicationMapping {
            class: ToolClass::BuiltInProcess,
            sandbox: SandboxProfile::ProcessRestricted,
        },
        (McpToolExecutionClass::ProcessBacked, McpServerKind::Remote) => PublicationMapping {
            class: ToolClass::BuiltInProcess,
            sandbox: SandboxProfile::ProcessRestricted,
        },
    }
}
