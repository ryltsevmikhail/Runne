impl FixtureMcpRuntime {
    /// Creates a fixture runtime without exporting an approval authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: FixtureMcpMode,
        identity: FixtureIdentity,
        tools: Vec<FixtureTool>,
        script: FixtureScript,
        allowlist: &[&str],
        limits: FixtureLimits,
        policy: FixtureApprovalPolicy,
        accounting_limit: u64,
    ) -> Result<Self, FixtureMcpFailure> {
        Self::new_with_approval_authority(
            mode,
            identity,
            tools,
            script,
            allowlist,
            limits,
            policy,
            accounting_limit,
        )
        .map(|(runtime, _)| runtime)
    }

    /// Creates a runtime and separately hands its injected fixture approval authority to the caller.
    /// Creates a fixture-only runtime and never activates an external backend.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_approval_authority(
        mode: FixtureMcpMode,
        identity: FixtureIdentity,
        tools: Vec<FixtureTool>,
        script: FixtureScript,
        allowlist: &[&str],
        limits: FixtureLimits,
        policy: FixtureApprovalPolicy,
        accounting_limit: u64,
    ) -> Result<(Self, FixtureApprovalAuthority), FixtureMcpFailure> {
        mode.activate()?;
        if tools.is_empty() || tools.len() > 64 || accounting_limit == 0 {
            return Err(FixtureMcpFailure::ToolDefinitionInvalid);
        }
        let names: BTreeSet<_> = tools.iter().map(|tool| tool.name().to_owned()).collect();
        if names.len() != tools.len() || allowlist.iter().any(|name| !names.contains(*name)) {
            return Err(FixtureMcpFailure::ToolDefinitionInvalid);
        }
        let allowlist = allowlist
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<BTreeSet<_>>();
        let issuer_digest = super::model::digest(&[
            b"fixture-issuer-v1",
            &FIXTURE_ISSUER_SEQUENCE
                .fetch_add(1, Ordering::Relaxed)
                .to_be_bytes(),
        ]);
        let mut definition_parts = vec![
            identity.definition_digest().to_vec(),
            script.digest().to_vec(),
            limits.max_bytes.to_be_bytes().to_vec(),
            limits.max_depth.to_be_bytes().to_vec(),
            limits.max_items.to_be_bytes().to_vec(),
            limits.max_string_bytes.to_be_bytes().to_vec(),
            vec![policy as u8],
            accounting_limit.to_be_bytes().to_vec(),
            b"fixture-in-process-transport-v1".to_vec(),
        ];
        definition_parts.extend(
            tools
                .iter()
                .map(FixtureTool::definition_digest)
                .map(|digest| digest.to_vec()),
        );
        definition_parts.extend(allowlist.iter().map(|name| name.as_bytes().to_vec()));
        let definition_refs = definition_parts
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let definition_digest =
            super::model::digest_domain(b"GOCODE_MCP_FIXTURE_DEFINITION_V1\0", &definition_refs);
        Ok((
            Self {
                mode,
                identity,
                tools,
                script,
                allowlist,
                limits,
                policy,
                definition_digest,
                issuer_digest,
                state: Arc::new(Mutex::new(FixtureState {
                    active: None,
                    reconnect_required: None,
                    reconnect_identity: None,
                    tick: 0,
                    next_step: 0,
                    remaining: accounting_limit,
                    effects: BTreeMap::new(),
                    process_ledger: BTreeMap::new(),
                    audit: Vec::new(),
                    dispatches: 0,
                    selected_outcomes: BTreeMap::new(),
                    protocol_reservations: BTreeMap::new(),
                })),
                gateway: None,
                process_composition: None,
                process_gateway: None,
                process_generation: None,
            },
            FixtureApprovalAuthority { issuer_digest },
        ))
    }

    /// Authenticates one exact identity/runtime/session/generation/connection tuple.
    pub fn initialize(&mut self, request: FixtureInitialize) -> Result<(), FixtureMcpFailure> {
        self.mode.activate()?;
        self.identity.matches(&request)?;
        if request.generation == 0 {
            return Err(FixtureMcpFailure::GenerationMismatch);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
        if let Some(requirement) = &state.reconnect_required {
            let (connection_valid, generation) = match requirement {
                ReconnectRequirement::Exact(connection_id, generation) => {
                    (connection_id == &request.connection_id, generation)
                }
                ReconnectRequirement::Fresh(connection_id, generation) => {
                    (connection_id != &request.connection_id, generation)
                }
            };
            if !connection_valid {
                return Err(FixtureMcpFailure::ConnectionMismatch);
            }
            if *generation != request.generation {
                return Err(FixtureMcpFailure::GenerationMismatch);
            }
            if let Some(previous) = &state.reconnect_identity {
                if previous.runtime_id != request.runtime_id {
                    return Err(FixtureMcpFailure::ServerIdentityMismatch);
                }
                if previous.session_id != request.session_id {
                    return Err(FixtureMcpFailure::SessionMismatch);
                }
            }
            state.reconnect_required = None;
            state.reconnect_identity = None;
        }
        if let Some(active) = &state.active {
            if active.connection_id != request.connection_id {
                return Err(FixtureMcpFailure::ConnectionMismatch);
            }
            if active.runtime_id != request.runtime_id {
                return Err(FixtureMcpFailure::ServerIdentityMismatch);
            }
            if active.session_id != request.session_id {
                return Err(FixtureMcpFailure::SessionMismatch);
            }
            if active.generation != request.generation {
                return Err(FixtureMcpFailure::GenerationMismatch);
            }
        }
        state.active = Some(request);
        Ok(())
    }

    /// Advances only the monotonic virtual clock used by the immutable script.
    pub fn advance_clock(&mut self, tick: u64) -> Result<(), FixtureMcpFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
        if tick < state.tick {
            return Err(FixtureMcpFailure::InvalidStateTransition);
        }
        state.tick = tick;
        Ok(())
    }

    /// Reconnects with a new connection, invalidating all earlier publications and capabilities.
    pub fn reconnect(&mut self, connection_id: McpConnectionId) -> Result<(), FixtureMcpFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
        let active = state
            .active
            .clone()
            .ok_or(FixtureMcpFailure::InvalidStateTransition)?;
        if active.connection_id == connection_id {
            return Err(FixtureMcpFailure::ConnectionMismatch);
        }
        let generation = active
            .generation
            .checked_add(1)
            .ok_or(FixtureMcpFailure::GenerationMismatch)?;
        state.reconnect_required = Some(ReconnectRequirement::Exact(connection_id, generation));
        state.reconnect_identity = Some(active);
        state.active = None;
        self.gateway = None;
        Ok(())
    }

    /// Publishes an allowlist-filtered snapshot bound to the authenticated connection.
    pub fn discover(&mut self) -> Result<FixturePublication, FixtureMcpFailure> {
        let active = self
            .active()?
            .active
            .clone()
            .ok_or(FixtureMcpFailure::InvalidStateTransition)?;
        let descriptors = self
            .tools
            .iter()
            .map(|tool| {
                McpToolDescriptor::new_with_execution_class(
                    tool.name(),
                    tool.version(),
                    tool.input_schema().clone(),
                    tool.execution_class(),
                )
                .map_err(|_| FixtureMcpFailure::ToolDefinitionInvalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let allowed = self
            .allowlist
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let published = Arc::new(
            publish_mcp_tools(
                self.identity.server_id().clone(),
                McpServerKind::Local,
                descriptors,
                &allowed,
            )
            .map_err(|_| FixtureMcpFailure::ToolDefinitionInvalid)?,
        );
        let binding = McpDispatchBinding::new(
            self.identity.server_id().clone(),
            active.runtime_id.clone(),
            active.connection_id.clone(),
            active.session_id.clone(),
            active.generation,
            *published.discovery_digest(),
        )
        .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
        let bounds = ToolOutputBounds::new(
            self.limits.max_bytes,
            self.limits.max_items,
            self.limits.max_items,
        )
        .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
        self.activate_process_gateway(&binding, bounds)?;
        self.gateway = Some(McpToolGateway::new(
            FixtureAdmission,
            FixtureClient(Arc::clone(&self.state)),
            Arc::new(McpGenerationAuthority::new(&binding)),
            bounds,
        ));
        Ok(FixturePublication {
            published,
            binding,
            tools: self
                .tools
                .iter()
                .filter(|tool| self.allowlist.contains(tool.name()))
                .cloned()
                .map(|tool| (tool.name().to_owned(), tool))
                .collect(),
            state: Arc::clone(&self.state),
            limits: self.limits,
            policy: self.policy,
            issuer_digest: self.issuer_digest,
            definition_digest: self.definition_digest,
        })
    }

    /// Returns the canonical digest of the complete immutable fixture definition.
    pub const fn definition_digest(&self) -> [u8; 32] {
        self.definition_digest
    }
}
