/// Deterministic authenticated fixture server identity.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureIdentity {
    server_id: McpServerId,
    server_version: String,
    profile: String,
    protocol_version: String,
    definition_digest: [u8; 32],
}

impl FixtureIdentity {
    /// Creates a bounded identity without credentials or ambient configuration.
    pub fn new(
        server_id: McpServerId,
        server_version: impl Into<String>,
        profile: impl Into<String>,
        protocol_version: impl Into<String>,
    ) -> Result<Self, FixtureMcpFailure> {
        let server_version = checked_text(server_version.into())?;
        let profile = checked_text(profile.into())?;
        let protocol_version = checked_text(protocol_version.into())?;
        let definition_digest = digest(&[
            server_id.as_str().as_bytes(),
            server_version.as_bytes(),
            profile.as_bytes(),
            protocol_version.as_bytes(),
        ]);
        Ok(Self { server_id, server_version, profile, protocol_version, definition_digest })
    }

    pub(crate) fn matches(&self, request: &FixtureInitialize) -> Result<(), FixtureMcpFailure> {
        if self.server_id.as_str() != request.server_id
            || self.server_version != request.server_version
            || self.profile != request.profile
        {
            return Err(FixtureMcpFailure::ServerIdentityMismatch);
        }
        if self.protocol_version != request.protocol_version {
            return Err(FixtureMcpFailure::ProtocolVersionUnsupported);
        }
        Ok(())
    }

    /// Returns an opaque deterministic fixture-definition digest.
    pub const fn definition_digest(&self) -> [u8; 32] { self.definition_digest }
    pub(crate) const fn server_id(&self) -> &McpServerId { &self.server_id }
}

/// Exact initialization tuple authenticated by the fixture.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureInitialize {
    pub(crate) runtime_id: McpRuntimeInstanceId,
    pub(crate) session_id: McpSessionId,
    pub(crate) connection_id: McpConnectionId,
    pub(crate) generation: u64,
    server_id: String,
    server_version: String,
    profile: String,
    protocol_version: String,
}

impl FixtureInitialize {
    /// Captures the complete explicit initialization tuple.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime_id: McpRuntimeInstanceId,
        session_id: McpSessionId,
        connection_id: McpConnectionId,
        generation: u64,
        server_id: impl Into<String>,
        server_version: impl Into<String>,
        profile: impl Into<String>,
        protocol_version: impl Into<String>,
    ) -> Self {
        Self {
            runtime_id, session_id, connection_id, generation, server_id: server_id.into(),
            server_version: server_version.into(), profile: profile.into(),
            protocol_version: protocol_version.into(),
        }
    }
}
