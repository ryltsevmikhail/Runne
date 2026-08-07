fn activate_process_generation(
    gateway: &McpProcessToolGateway,
    composition: &FixtureProcessComposition,
    process_generation: &mut Option<u64>,
    expected_generation: u64,
    binding: &McpDispatchBinding,
) -> Result<(), FixtureMcpFailure> {
    let mut generation = gateway
        .prepare_generation_advance(expected_generation, binding)
        .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
    let mut authorization = composition
        .prepare_authorization_advance()
        .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;

    generation.apply_retaining_lock();
    authorization.apply_retaining_lock();
    *process_generation = Some(binding.generation());
    drop(generation);
    drop(authorization);
    Ok(())
}

impl FixtureMcpRuntime {
    /// Creates a fixture runtime with one sealed process composition and both approval authorities.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_process_authorities(
        mode: FixtureMcpMode,
        identity: FixtureIdentity,
        tools: Vec<FixtureTool>,
        script: FixtureScript,
        allowlist: &[&str],
        limits: FixtureLimits,
        policy: FixtureApprovalPolicy,
        accounting_limit: u64,
        composition: FixtureProcessComposition,
    ) -> Result<
        (
            Self,
            FixtureApprovalAuthority,
            FixtureProcessApprovalAuthority,
        ),
        FixtureMcpFailure,
    > {
        let (mut runtime, approval) = Self::new_with_approval_authority(
            mode,
            identity,
            tools,
            script,
            allowlist,
            limits,
            policy,
            accounting_limit,
        )?;
        let process_approval = composition.authority();
        runtime.process_composition = Some(composition);
        Ok((runtime, approval, process_approval))
    }

    fn activate_process_gateway(
        &mut self,
        binding: &McpDispatchBinding,
        bounds: ToolOutputBounds,
    ) -> Result<(), FixtureMcpFailure> {
        let has_process_tool = self.tools.iter().any(|tool| {
            self.allowlist.contains(tool.name())
                && tool.execution_class() == crate::McpToolExecutionClass::ProcessBacked
        });
        if has_process_tool {
            match (self.process_gateway.as_ref(), self.process_generation) {
                (Some(_), None) => return Err(FixtureMcpFailure::InvalidStateTransition),
                (Some(_), Some(generation)) if generation == binding.generation() => {}
                (Some(gateway), Some(generation)) => activate_process_generation(
                    gateway,
                    self.process_composition
                        .as_ref()
                        .expect("gateway has composition"),
                    &mut self.process_generation,
                    generation,
                    binding,
                )?,
                (None, _) if self.process_composition.is_some() => {
                    let composition = self.process_composition.as_mut().expect("checked above");
                    self.process_gateway = composition
                        .compose_gateway(Arc::new(McpGenerationAuthority::new(binding)), bounds);
                    if self.process_gateway.is_some() {
                        self.process_generation = Some(binding.generation());
                    }
                }
                (None, _) => {}
            }
        }
        Ok(())
    }

    /// Returns safe process-composition metadata without authorization material.
    #[must_use]
    pub fn process_composition_metadata(&self) -> Option<super::FixtureProcessCompositionMetadata> {
        self.process_composition
            .as_ref()
            .map(|composition| composition.metadata(self.process_generation))
    }

    #[cfg(test)]
    pub(crate) fn process_gateway_present(&self) -> bool {
        self.process_gateway.is_some()
    }

    #[cfg(test)]
    pub(super) fn process_generation_authority_for_test(
        &self,
    ) -> Option<Arc<McpGenerationAuthority>> {
        self.process_gateway
            .as_ref()
            .map(McpProcessToolGateway::generation_for_test)
    }
}
