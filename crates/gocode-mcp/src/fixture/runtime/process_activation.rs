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
    #[cfg(test)]
    pub(in crate::fixture) fn new_with_process_authorities(
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
                    let ledger = Arc::new(self.process_ledger_port());
                    let composition = self.process_composition.as_mut().expect("checked above");
                    self.process_gateway = composition
                        .compose_gateway(
                            Arc::new(McpGenerationAuthority::new(binding)),
                            ledger,
                            bounds,
                        );
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
    #[cfg(test)]
    pub(in crate::fixture) fn process_composition_metadata(
        &self,
    ) -> Option<super::process::FixtureProcessCompositionMetadata> {
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

    #[cfg(test)]
    pub(in crate::fixture) fn process_effect_admission_count_for_test(&self) -> Option<usize> {
        self.process_gateway
            .as_ref()
            .map(McpProcessToolGateway::effect_admission_count)
    }

    #[cfg(test)]
    pub(in crate::fixture) fn process_host_dispatch_count_for_test(&self) -> Option<usize> {
        self.process_gateway
            .as_ref()
            .map(McpProcessToolGateway::host_dispatch_count_for_test)
    }

    #[cfg(test)]
    pub(in crate::fixture) fn pause_process_gateway_after_settlement_for_test(
        &self,
        settled: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        self.process_gateway
            .as_ref()
            .expect("gateway is active")
            .pause_after_settlement_for_test(settled, release);
    }

    #[cfg(test)]
    pub(in crate::fixture) fn dispatch_process_gateway_for_test(
        &self,
        key: super::process_call::ProcessEffectKey,
        payload: super::process_call::ProcessDispatchPayload,
    ) -> Result<
        process_ledger::ProcessPhaseOutcome,
        super::process_gateway::ledger_port::TestDispatchError,
    > {
        self.process_gateway
            .as_ref()
            .ok_or(super::process_gateway::ledger_port::TestDispatchError::ReservationUnavailable)?
            .dispatch_for_test(self, key, payload)
    }

    #[cfg(test)]
    pub(in crate::fixture) fn dispatch_reserved_process_gateway_for_test(
        &self,
        receipt: process_ledger::ProcessReservationReceipt,
        payload: super::process_call::ProcessDispatchPayload,
    ) -> Result<
        process_ledger::ProcessPhaseOutcome,
        super::process_gateway::ledger_port::TestDispatchError,
    > {
        self.process_gateway
            .as_ref()
            .ok_or(super::process_gateway::ledger_port::TestDispatchError::ReservationUnavailable)?
            .dispatch_reserved_for_test(receipt, payload)
    }
}
