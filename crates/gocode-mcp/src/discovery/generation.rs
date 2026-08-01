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
