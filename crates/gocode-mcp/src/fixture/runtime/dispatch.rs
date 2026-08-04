struct UncertainDispatchContext {
    key: EffectKey,
    invocation: String,
    connection: String,
    generation: u64,
    bytes: usize,
}

impl FixtureMcpRuntime {
    /// Dispatches only a current issued capability through `McpToolGateway`.
    pub fn dispatch(&mut self, capability: &mut FixtureCallCapability, approval: Option<&FixtureApproval>) -> Result<FixtureCallResult, FixtureMcpFailure> {
        let mut state = self.state.lock().map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
        if capability.issuer_digest != self.issuer_digest || capability.definition_digest != self.definition_digest {
            return Err(FixtureMcpFailure::CapabilityMissing);
        }
        if let Some((key, result)) = state.effects.iter().find(|(key, _)| key.invocation_id == capability.invocation_id) {
            if key != &capability.effect_key { return Err(FixtureMcpFailure::InvocationConflict); }
            return match result {
                FixtureCallResult::Completed => Ok(*result),
                FixtureCallResult::Uncertain => Err(FixtureMcpFailure::DispatchUncertain),
                FixtureCallResult::Cancelled => Err(FixtureMcpFailure::Cancelled),
                FixtureCallResult::Disconnected => Err(FixtureMcpFailure::TimedOut),
            };
        }
        let active = state.active.as_ref().cloned().ok_or(FixtureMcpFailure::InvalidStateTransition)?;
        if active.connection_id.as_str() != capability.connection_id { return Err(FixtureMcpFailure::ConnectionMismatch); }
        if active.generation != capability.generation { return Err(FixtureMcpFailure::GenerationMismatch); }
        if state.tick > capability.expires_at { return Err(FixtureMcpFailure::CapabilityExpired); }
        if capability.capability.is_none() { return Err(FixtureMcpFailure::CapabilityConsumed); }
        match self.policy {
            FixtureApprovalPolicy::AlwaysDeny => return Err(FixtureMcpFailure::ApprovalRequired),
            FixtureApprovalPolicy::ExplicitPerCall | FixtureApprovalPolicy::PreApprovedExactIntent
                if approval != Some(&FixtureApproval(capability.approval_digest)) => return Err(FixtureMcpFailure::ApprovalMismatch),
            _ => {}
        }
        let tool = self.tools.iter().find(|tool| tool.name() == capability.tool_name)
            .ok_or(FixtureMcpFailure::ToolNotAllowed)?;
        if !self.allowlist.contains(tool.name()) { return Err(FixtureMcpFailure::ToolNotAllowed); }
        if state.remaining == 0 { return Err(FixtureMcpFailure::AccountingDenied); }
        let step = self.script.steps.get(state.next_step).cloned().ok_or(FixtureMcpFailure::InvalidStateTransition)?;
        if state.tick < step.available_at_tick { return Err(FixtureMcpFailure::TimedOut); }
        state.next_step += 1;
        match step.outcome {
            FixtureStepOutcome::CancelBeforeDispatch => {
                capability.capability.take(); state.effects.insert(capability.effect_key.clone(), FixtureCallResult::Cancelled);
                return Err(FixtureMcpFailure::Cancelled);
            }
            FixtureStepOutcome::DisconnectBeforeDispatch => {
                capability.capability.take(); state.effects.insert(capability.effect_key.clone(), FixtureCallResult::Disconnected);
                state.reconnect_required = Some(ReconnectRequirement::Fresh(
                    active.connection_id.clone(),
                    active.generation.checked_add(1).ok_or(FixtureMcpFailure::GenerationMismatch)?,
                ));
                state.reconnect_identity = Some(active); state.active = None; self.gateway = None;
                return Err(FixtureMcpFailure::TimedOut);
            }
            _ => state.remaining -= 1,
        }
        if matches!(step.outcome, FixtureStepOutcome::Response(_)) {
            state.selected_outcomes.insert(capability.invocation_id.clone(), step.outcome.clone());
        }
        let context = UncertainDispatchContext {
            key: capability.effect_key.clone(),
            invocation: capability.invocation_id.clone(),
            connection: active.connection_id.as_str().to_owned(),
            generation: active.generation,
            bytes: capability.bytes,
        };
        drop(state);
        let gateway_capability = capability.capability.take().ok_or(FixtureMcpFailure::CapabilityConsumed)?;
        let handle = match self.gateway.as_ref().ok_or(FixtureMcpFailure::InvalidStateTransition)?.dispatch(gateway_capability) {
            Ok(handle) => handle,
            Err(_) => return self.mark_uncertain(&context, None, FixtureMcpFailure::DispatchUncertain),
        };
        let terminal = match step.outcome {
            FixtureStepOutcome::Response(value) => self.complete_response(&handle, &context.invocation, capability.request_digest, tool.output_schema(), value),
            FixtureStepOutcome::AccountingMismatch => Err(FixtureMcpFailure::AccountingMismatch),
            FixtureStepOutcome::ProtocolError | FixtureStepOutcome::AcceptedThenLost | FixtureStepOutcome::StaleResponse => Err(FixtureMcpFailure::DispatchUncertain),
            _ => Err(FixtureMcpFailure::InvalidStateTransition),
        };
        match terminal {
            Ok(result) => {
                let mut state = self.state.lock().map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
                state.effects.insert(context.key, result);
                state.audit.push(FixtureAuditRecord { invocation_digest: super::model::digest(&[context.invocation.as_bytes()]), connection_digest: super::model::digest(&[context.connection.as_bytes()]), generation: context.generation, bytes: context.bytes, uncertain: false });
                Ok(result)
            }
            Err(error) => self.mark_uncertain(&context, Some(&handle), error),
        }
    }

    fn mark_uncertain(&self, context: &UncertainDispatchContext, handle: Option<&ToolExecutionHandle>, error: FixtureMcpFailure) -> Result<FixtureCallResult, FixtureMcpFailure> {
        if let Some(handle) = handle {
            self.gateway.as_ref().ok_or(FixtureMcpFailure::InvalidStateTransition)?
                .mark_uncertain(&context.invocation, context.key.request_digest, handle)
                .map_err(|_| FixtureMcpFailure::DispatchUncertain)?;
        }
        let mut state = self.state.lock().map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
        state.effects.insert(context.key.clone(), FixtureCallResult::Uncertain);
        state.audit.push(FixtureAuditRecord { invocation_digest: super::model::digest(&[context.invocation.as_bytes()]), connection_digest: super::model::digest(&[context.connection.as_bytes()]), generation: context.generation, bytes: context.bytes, uncertain: true });
        Err(error)
    }

    /// Returns remaining synthetic numeric accounting capacity.
    pub fn accounting_remaining(&self) -> u64 { self.state.lock().map(|state| state.remaining).unwrap_or(0) }
    /// Returns safe typed audit metadata only.
    pub fn audit(&self) -> Vec<FixtureAuditRecord> { self.state.lock().map(|state| state.audit.clone()).unwrap_or_default() }
    /// Returns dispatches which reached the in-process gateway effect boundary.
    pub fn dispatch_count(&self) -> u64 { self.state.lock().map(|state| state.dispatches).unwrap_or(0) }
    /// Returns unconsumed immutable script steps for deterministic fixture observation.
    pub fn pending_script_steps(&self) -> usize {
        self.state.lock().map(|state| self.script.steps.len().saturating_sub(state.next_step)).unwrap_or(0)
    }
    fn active(&self) -> Result<std::sync::MutexGuard<'_, FixtureState>, FixtureMcpFailure> {
        let state = self.state.lock().map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
        if state.active.is_none() { Err(FixtureMcpFailure::InvalidStateTransition) } else { Ok(state) }
    }
    fn complete_response(&self, handle: &ToolExecutionHandle, invocation: &str, request_digest: [u8; 32], output_schema: &Value, value: Value) -> Result<FixtureCallResult, FixtureMcpFailure> {
        super::schema::validate_value(&value, &self.limits).map_err(|_| FixtureMcpFailure::ResponseTooLarge)?;
        super::schema::reject_secret_material(&value)?;
        super::schema::validate_instance(output_schema, &value).map_err(|_| FixtureMcpFailure::OutputSchemaMismatch)?;
        self.gateway.as_ref().ok_or(FixtureMcpFailure::InvalidStateTransition)?.complete_protocol(
            invocation,
            request_digest,
            handle,
        ).map_err(|_| FixtureMcpFailure::DispatchUncertain)?;
        Ok(FixtureCallResult::Completed)
    }
}
