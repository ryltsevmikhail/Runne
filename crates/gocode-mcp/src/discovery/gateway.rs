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
