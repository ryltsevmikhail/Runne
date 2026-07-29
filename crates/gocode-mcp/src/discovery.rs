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

/// Exact generation-bound MCP dispatch identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpDispatchBinding {
    server_id: McpServerId,
    runtime_id: McpRuntimeInstanceId,
    connection_id: McpConnectionId,
    session_id: McpSessionId,
    generation: u64,
    discovery_digest: [u8; 32],
    binding_digest: [u8; 32],
}

impl McpDispatchBinding {
    /// Constructs a complete dispatch binding.
    pub fn new(
        server_id: McpServerId,
        runtime_id: McpRuntimeInstanceId,
        connection_id: McpConnectionId,
        session_id: McpSessionId,
        generation: u64,
        discovery_digest: [u8; 32],
    ) -> Result<Self, InvalidMcpIdentity> {
        if generation == 0 || discovery_digest == [0; 32] {
            return Err(InvalidMcpIdentity::InvalidCharacter);
        }
        let binding_digest = binding_digest(
            &server_id,
            &runtime_id,
            &connection_id,
            &session_id,
            generation,
            discovery_digest,
        );
        Ok(Self {
            server_id,
            runtime_id,
            connection_id,
            session_id,
            generation,
            discovery_digest,
            binding_digest,
        })
    }

    /// Exact authority generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Runtime-owned MCP generation authority.
pub struct McpGenerationAuthority {
    current: RwLock<McpGenerationBinding>,
}

struct McpGenerationBinding {
    generation: u64,
    binding_digest: [u8; 32],
}

impl McpGenerationAuthority {
    /// Creates authority for one exact current binding.
    pub fn new(binding: &McpDispatchBinding) -> Self {
        Self {
            current: RwLock::new(McpGenerationBinding {
                generation: binding.generation,
                binding_digest: binding.binding_digest,
            }),
        }
    }

    /// Advances monotonically only when no dispatch read lease reaches an
    /// external effect boundary.
    pub fn try_advance(
        &self,
        binding: &McpDispatchBinding,
    ) -> Result<(), McpGenerationAdvanceError> {
        let mut current = match self.current.try_write() {
            Ok(current) => current,
            Err(TryLockError::WouldBlock) => return Err(McpGenerationAdvanceError::Busy),
            Err(TryLockError::Poisoned(_)) => return Err(McpGenerationAdvanceError::Unavailable),
        };
        if binding.generation <= current.generation {
            return Err(McpGenerationAdvanceError::InvalidGeneration);
        }
        *current = McpGenerationBinding {
            generation: binding.generation,
            binding_digest: binding.binding_digest,
        };
        Ok(())
    }

    fn claim_dispatch(
        &self,
        binding: &McpDispatchBinding,
    ) -> Result<McpGenerationReadPermit<'_>, McpGenerationClaimError> {
        let guard = self
            .current
            .read()
            .map_err(|_| McpGenerationClaimError::Unavailable)?;
        if guard.generation != binding.generation || guard.binding_digest != binding.binding_digest
        {
            return Err(McpGenerationClaimError::Stale);
        }
        Ok(McpGenerationReadPermit {
            binding_digest: binding.binding_digest,
            _guard: guard,
        })
    }
}

/// Generation advance failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpGenerationAdvanceError {
    /// Generation must be non-zero and strictly increase.
    InvalidGeneration,
    /// A dispatch lease currently fences cutover.
    Busy,
    /// Generation state is unavailable.
    Unavailable,
}

/// Read permit held through gateway admission and client dispatch.
struct McpGenerationReadPermit<'a> {
    binding_digest: [u8; 32],
    _guard: RwLockReadGuard<'a, McpGenerationBinding>,
}

impl McpGenerationReadPermit<'_> {
    fn matches(&self, binding: &McpDispatchBinding) -> bool {
        self.binding_digest == binding.binding_digest
    }
}

/// Generation claim failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpGenerationClaimError {
    /// Binding belongs to a stale generation.
    Stale,
    /// Generation authority is unavailable.
    Unavailable,
}

/// MCP call mediation failure.
#[derive(Debug, PartialEq, Eq)]
pub enum McpToolGatewayError {
    /// Generation authority rejected the binding.
    StaleGeneration,
    /// Binding/tool namespace was inconsistent.
    InvalidBinding,
    /// Pending call state was unavailable.
    Unavailable,
    /// ToolGateway returned the authoritative disposition.
    Gateway(ToolGatewayError),
}

#[derive(Clone)]
struct PendingCall {
    digest: [u8; 32],
    message: McpNormalizedMessage,
}

type PendingCalls = Arc<Mutex<BTreeMap<String, PendingCall>>>;

struct McpGatewayExecutor<C> {
    client: Mutex<C>,
    pending: PendingCalls,
}

impl<C: McpClientPort + Send> ToolExecutorPort for McpGatewayExecutor<C> {
    fn start(
        &self,
        request: &ToolDispatchRequest,
        admission: &EffectAdmission,
    ) -> Result<ToolExecutionHandle, ToolExecutorError> {
        if admission.permit_id.is_empty() {
            return Err(ToolExecutorError::Rejected);
        }
        let pending = self
            .pending
            .lock()
            .map_err(|_| ToolExecutorError::Unavailable)?
            .remove(&request.invocation_id)
            .ok_or(ToolExecutorError::Rejected)?;
        if pending.digest != request.request_digest {
            return Err(ToolExecutorError::Rejected);
        }
        self.client
            .lock()
            .map_err(|_| ToolExecutorError::Unavailable)?
            .dispatch(&pending.message)
            .map_err(|_| ToolExecutorError::Unavailable)?;
        Ok(ToolExecutionHandle {
            execution_id: format!("mcp:{}", request.invocation_id),
        })
    }

    fn signal_cancel(&self, handle: &ToolExecutionHandle) -> Result<(), ToolExecutorError> {
        self.client
            .lock()
            .map_err(|_| ToolExecutorError::Unavailable)?
            .dispatch(&McpNormalizedMessage::request(
                None,
                "notifications/cancelled".into(),
                json!({"execution": handle.execution_id}),
            ))
            .map_err(|_| ToolExecutorError::Unavailable)
    }
}

/// MCP tool caller that can reach the client only through ToolGateway.
pub struct McpToolGateway<A, C> {
    gateway: ToolGateway<A, McpGatewayExecutor<C>>,
    generation: Arc<McpGenerationAuthority>,
    pending: PendingCalls,
}

impl<A, C> McpToolGateway<A, C>
where
    A: ToolAdmissionPort,
    C: McpClientPort + Send,
{
    /// Constructs mandatory gateway mediation around one project client.
    pub fn new(
        admission: A,
        client: C,
        generation: Arc<McpGenerationAuthority>,
        bounds: ToolOutputBounds,
    ) -> Self {
        let pending = Arc::new(Mutex::new(BTreeMap::new()));
        Self {
            gateway: ToolGateway::new(
                admission,
                McpGatewayExecutor {
                    client: Mutex::new(client),
                    pending: Arc::clone(&pending),
                },
                bounds,
            ),
            generation,
            pending,
        }
    }

    /// Claims generation, builds an exact binding and dispatches through every
    /// ToolGateway admission stage before the client can observe the call.
    pub fn dispatch(
        &self,
        capability: McpToolDispatchCapability,
    ) -> Result<ToolExecutionHandle, McpToolGatewayError> {
        let permit = self
            .generation
            .claim_dispatch(&capability.binding)
            .map_err(|_| McpToolGatewayError::StaleGeneration)?;
        if !permit.matches(&capability.binding) {
            return Err(McpToolGatewayError::InvalidBinding);
        }
        let McpToolDispatchCapability {
            binding,
            tool_ref,
            invocation_id,
            input,
            server_tool_name,
            request_digest,
        } = capability;
        let invocation_id = invocation_id.as_str().to_owned();
        let message = McpNormalizedMessage::request(
            Some(McpRequestId::String(invocation_id.clone())),
            MCP_TOOLS_CALL_METHOD.into(),
            json!({
                "name": server_tool_name,
                "arguments": input,
                "runtime": binding.runtime_id.as_str(),
                "session": binding.session_id.as_str(),
            }),
        );
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| McpToolGatewayError::Unavailable)?;
            match pending.get(&invocation_id) {
                Some(existing) if existing.digest != request_digest => {
                    return Err(McpToolGatewayError::Gateway(
                        ToolGatewayError::DigestConflict,
                    ));
                }
                Some(_) => {}
                None => {
                    pending.insert(
                        invocation_id.clone(),
                        PendingCall {
                            digest: request_digest,
                            message,
                        },
                    );
                }
            }
        }
        let result = self
            .gateway
            .dispatch(ToolDispatchRequest {
                invocation_id: invocation_id.clone(),
                request_digest,
                binding: ToolDispatchBinding::new(
                    tool_ref,
                    binding.connection_id.as_str().to_owned(),
                    binding.binding_digest,
                    binding.generation,
                    binding.discovery_digest,
                ),
            })
            .map_err(McpToolGatewayError::Gateway);
        self.pending
            .lock()
            .map_err(|_| McpToolGatewayError::Unavailable)?
            .remove(&invocation_id);
        result
    }
}

fn discovery_digest(server_id: &McpServerId, tools: &[McpToolDescriptor]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GOCODE_MCP_DISCOVERY_V1\0");
    hash_field(&mut hasher, server_id.as_str().as_bytes());
    hasher.update((tools.len() as u64).to_be_bytes());
    for tool in tools {
        hash_field(&mut hasher, tool.name.as_bytes());
        hash_field(&mut hasher, tool.version.to_string().as_bytes());
        let schema =
            serde_json::to_vec(&tool.input_schema).expect("serde_json::Value always serializes");
        hash_field(&mut hasher, &schema);
    }
    hasher.finalize().into()
}

fn binding_digest(
    server_id: &McpServerId,
    runtime_id: &McpRuntimeInstanceId,
    connection_id: &McpConnectionId,
    session_id: &McpSessionId,
    generation: u64,
    discovery_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GOCODE_MCP_DISPATCH_BINDING_V1\0");
    for value in [
        server_id.as_str(),
        runtime_id.as_str(),
        connection_id.as_str(),
        session_id.as_str(),
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    hasher.update(generation.to_be_bytes());
    hasher.update(discovery_digest);
    hasher.finalize().into()
}

fn call_digest(
    binding: &McpDispatchBinding,
    tool_ref: &ToolRef,
    invocation_id: &McpInvocationId,
    input: &Value,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GOCODE_MCP_TOOL_CALL_V1\0");
    hasher.update(binding.binding_digest);
    hash_field(&mut hasher, MCP_TOOLS_CALL_METHOD.as_bytes());
    hash_field(&mut hasher, MCP_REQUEST_CLASS);
    hash_field(&mut hasher, invocation_id.as_str().as_bytes());
    hash_field(&mut hasher, tool_ref.tool_id().as_str().as_bytes());
    hash_field(&mut hasher, tool_ref.version().to_string().as_bytes());
    let input = serde_json::to_vec(input).expect("serde_json::Value always serializes");
    hash_field(&mut hasher, &input);
    hasher.finalize().into()
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}
