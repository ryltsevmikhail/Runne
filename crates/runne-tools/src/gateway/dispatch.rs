impl<A, E> ToolGateway<A, E>
where
    A: ToolAdmissionPort,
    E: ToolExecutorPort,
{
    /// Constructs a gateway with exact output bounds.
    pub fn new(admission: A, executor: E, bounds: ToolOutputBounds) -> Self {
        Self {
            admission,
            executor,
            bounds,
            state: Mutex::new(BTreeMap::new()),
        }
    }

    /// Runs all gates in fixed order and returns no handle before effect admission.
    pub fn dispatch(
        &self,
        request: ToolDispatchRequest,
    ) -> Result<ToolExecutionHandle, ToolGatewayError> {
        let mut state = self.lock_state()?;
        if let Some(existing) = state.get(&request.invocation_id) {
            ensure_request(existing, &request)?;
            return existing
                .handle
                .clone()
                .ok_or(ToolGatewayError::UncertainAfterAdmission);
        }

        for stage in [
            GateStage::Capability,
            GateStage::Approval,
            GateStage::Budget,
            GateStage::Containment,
        ] {
            if self.admission.check(stage, &request)? != ToolAdmissionDecision::Passed {
                return Err(ToolAdmissionError::Unavailable.into());
            }
        }
        let effect = match self.admission.check(GateStage::EffectAdmission, &request)? {
            ToolAdmissionDecision::Winner(effect) => effect,
            ToolAdmissionDecision::Existing(handle) => {
                state.insert(
                    request.invocation_id,
                    InvocationState {
                        digest: request.request_digest,
                        binding: request.binding,
                        handle: Some(handle.clone()),
                        cancel_signalled: false,
                        terminal: None,
                    },
                );
                return Ok(handle);
            }
            ToolAdmissionDecision::Uncertain => {
                state.insert(
                    request.invocation_id,
                    InvocationState {
                        digest: request.request_digest,
                        binding: request.binding,
                        handle: None,
                        cancel_signalled: false,
                        terminal: Some(ToolTerminalDisposition::Uncertain),
                    },
                );
                return Err(ToolGatewayError::UncertainAfterAdmission);
            }
            ToolAdmissionDecision::Passed => {
                return Err(ToolAdmissionError::Unavailable.into());
            }
        };
        let handle = match self.executor.start(&request, &effect) {
            Ok(handle) => handle,
            Err(_) => {
                state.insert(
                    request.invocation_id,
                    InvocationState {
                        digest: request.request_digest,
                        binding: request.binding,
                        handle: None,
                        cancel_signalled: false,
                        terminal: Some(ToolTerminalDisposition::Uncertain),
                    },
                );
                return Err(ToolGatewayError::UncertainAfterAdmission);
            }
        };
        state.insert(
            request.invocation_id,
            InvocationState {
                digest: request.request_digest,
                binding: request.binding,
                handle: Some(handle.clone()),
            cancel_signalled: false,
            terminal: None,
            },
        );
        Ok(handle)
    }

    /// Durably identifies duplicate cancellation signals.
    pub fn signal_cancel(
        &self,
        request: ToolCancelRequest,
    ) -> Result<ToolCancelDisposition, ToolGatewayError> {
        let mut state = self.lock_state()?;
        let invocation =
            exact_invocation_mut(&mut state, &request.invocation_id, request.request_digest)?;
        ensure_handle(invocation, &request.handle)?;
        if invocation.cancel_signalled {
            return Ok(ToolCancelDisposition::AlreadySignalled);
        }
        let handle = invocation
            .handle
            .as_ref()
            .ok_or(ToolGatewayError::UncertainAfterAdmission)?;
        self.executor.signal_cancel(handle)?;
        invocation.cancel_signalled = true;
        Ok(ToolCancelDisposition::Signalled)
    }

    /// Records a durable, idempotent uncertain terminal result for one handle.
    pub fn mark_uncertain(
        &self,
        invocation_id: &str,
        request_digest: [u8; 32],
        handle: &ToolExecutionHandle,
    ) -> Result<ToolTerminalDisposition, ToolGatewayError> {
        let mut state = self.lock_state()?;
        let invocation = exact_invocation_mut(&mut state, invocation_id, request_digest)?;
        ensure_handle(invocation, handle)?;
        let terminal = invocation
            .terminal
            .get_or_insert(ToolTerminalDisposition::Uncertain);
        Ok(terminal.clone())
    }

    fn lock_state(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<String, InvocationState>>, ToolGatewayError> {
        self.state.lock().map_err(|_| ToolGatewayError::Unavailable)
    }

}

impl<A, E> ToolGateway<A, E>
where
    A: ToolAdmissionPort,
    E: ToolExecutorPort<CompletionMode = ProcessCompletion>,
{
    /// Produces the only terminal transition for a process executor.
    pub fn close(
        &self,
        request: ToolCloseRequest,
    ) -> Result<ToolTerminalDisposition, ToolGatewayError> {
        let mut state = self.lock_state()?;
        let invocation =
            exact_invocation_mut(&mut state, &request.invocation_id, request.request_digest)?;
        ensure_handle(invocation, &request.handle)?;
        if let Some(terminal) = &invocation.terminal {
            return Ok(terminal.clone());
        }
        let terminal = if !request.evidence.is_complete() {
            ToolTerminalDisposition::Uncertain
        } else {
            ToolOutput::bound(request.output, self.bounds)
                .map(ToolTerminalDisposition::Completed)
                .unwrap_or(ToolTerminalDisposition::Uncertain)
        };
        invocation.terminal = Some(terminal.clone());
        Ok(terminal)
    }
}

impl<A, E> ToolGateway<A, E>
where
    A: ToolAdmissionPort,
    E: ProtocolToolExecutorPort<CompletionMode = ProtocolCompletion>,
{
    /// Closes a protocol effect only after its executor confirms a private claim.
    pub fn close_protocol(
        &self,
        request: ToolProtocolCloseRequest,
    ) -> Result<ToolTerminalDisposition, ToolGatewayError> {
        let mut state = self.lock_state()?;
        let invocation =
            exact_invocation_mut(&mut state, &request.invocation_id, request.request_digest)?;
        ensure_handle(invocation, &request.handle)?;
        if let Some(terminal) = &invocation.terminal {
            return Ok(terminal.clone());
        }
        self.executor
            .confirm_protocol_completion(&request)
            .map_err(|_| ToolGatewayError::ProtocolClosureConflict)?;
        let output = ToolOutput::bound(RawToolOutput::default(), self.bounds)
            .map_err(|_| ToolGatewayError::ProtocolClosureConflict)?;
        let terminal = ToolTerminalDisposition::Completed(output);
        invocation.terminal = Some(terminal.clone());
        Ok(terminal)
    }
}
