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

    /// Produces the only terminal transition.
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
            match ToolOutput::bound(request.output, self.bounds) {
                Ok(output) => ToolTerminalDisposition::Completed(output),
                Err(()) => ToolTerminalDisposition::Uncertain,
            }
        };
        invocation.terminal = Some(terminal.clone());
        Ok(terminal)
    }

    fn lock_state(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<String, InvocationState>>, ToolGatewayError> {
        self.state.lock().map_err(|_| ToolGatewayError::Unavailable)
    }
}
