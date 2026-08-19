use runne_platform_ports::process::{
    MonotonicDeadline, NoProcessStartedEvidenceV1, ProcessLaunchEvidenceV1, ProcessLaunchOutcomeV1,
    ProcessLifecycleBindingV1, ProcessPlatformFailure, ProcessPlatformPort,
    ProcessPlatformRequestV1, ProcessTerminalDispositionV1, ProcessTerminalEvidenceV1,
};

use super::{
    ProcessControlPortV1, VirtualGraceScriptV1, VirtualLaunchScriptV1, VirtualProcessCallV1,
    VirtualProcessTreeFixtureV1,
};

/// Scripted terminal observation behavior of the deterministic virtual tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum VirtualCompletionScriptV1 {
    /// The exact tree remains running.
    Pending,
    /// Exact verified terminal completion is observed.
    Complete,
    /// Exact terminal evidence has a configured verification mismatch.
    Mismatch,
    /// Terminal observation cannot establish evidence.
    Unavailable,
}

impl VirtualProcessTreeFixtureV1 {
    pub(super) fn set_completion_script(
        &self,
        script: VirtualCompletionScriptV1,
    ) -> Result<(), super::VirtualFixtureErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| super::VirtualFixtureErrorV1::Poisoned)?;
        state.completion = script;
        if script == VirtualCompletionScriptV1::Mismatch
            && state.owner_verification
                == runne_platform_ports::process::ProcessOwnerVerificationV1::Verified
            && state.tree_cleanup == runne_platform_ports::process::ProcessTreeCleanupV1::Verified
        {
            state.owner_verification =
                runne_platform_ports::process::ProcessOwnerVerificationV1::Mismatch;
        }
        Ok(())
    }

    pub(super) fn reject_graceful(&self) -> Result<(), super::VirtualFixtureErrorV1> {
        self.state
            .lock()
            .map_err(|_| super::VirtualFixtureErrorV1::Poisoned)?
            .graceful_rejected = true;
        Ok(())
    }
}

impl ProcessPlatformPort for VirtualProcessTreeFixtureV1 {
    type Prepared = ();

    fn validate_and_prepare(
        &self,
        request: &ProcessPlatformRequestV1,
        deadline: MonotonicDeadline,
    ) -> Result<Self::Prepared, ProcessPlatformFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProcessPlatformFailure::ProcessUncertain)?;
        state.calls.push(VirtualProcessCallV1::ValidateAndPrepare);
        state.prepare_deadline = Some(deadline);
        if state
            .observed_executable
            .as_ref()
            .is_some_and(|observed| observed != request.executable())
            || state.prepare_rejected
        {
            Err(ProcessPlatformFailure::ExecutableVerificationFailed)
        } else {
            Ok(())
        }
    }

    fn launch(
        &self,
        _: Self::Prepared,
        binding: &ProcessLifecycleBindingV1,
        deadline: MonotonicDeadline,
    ) -> Result<ProcessLaunchOutcomeV1, ProcessPlatformFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProcessPlatformFailure::ProcessUncertain)?;
        state.calls.push(VirtualProcessCallV1::Launch);
        state.launch_deadline = Some(deadline);
        match state.launch {
            VirtualLaunchScriptV1::Launch => {
                state.held_binding = state
                    .control_binding
                    .clone()
                    .or_else(|| Some(binding.clone()));
                let evidence_binding = state.launch_evidence_binding.as_ref().unwrap_or(binding);
                Ok(ProcessLaunchOutcomeV1::Launched(
                    ProcessLaunchEvidenceV1::new(evidence_binding, [1; 32])?,
                ))
            }
            VirtualLaunchScriptV1::NoProcessStarted => {
                Ok(ProcessLaunchOutcomeV1::NoProcessStarted(
                    NoProcessStartedEvidenceV1::new(binding, [2; 32])?,
                ))
            }
            VirtualLaunchScriptV1::Ambiguous => Err(ProcessPlatformFailure::LaunchEvidenceMissing),
        }
    }

    fn terminate(
        &self,
        binding: &ProcessLifecycleBindingV1,
        _: MonotonicDeadline,
    ) -> Result<ProcessTerminalEvidenceV1, ProcessPlatformFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProcessPlatformFailure::ProcessUncertain)?;
        state.calls.push(VirtualProcessCallV1::Terminate);
        if state.held_binding.as_ref() != Some(binding) {
            return Err(ProcessPlatformFailure::LifecycleControlMismatch);
        }
        if state.force_ambiguous {
            return Err(ProcessPlatformFailure::TerminationUnverified);
        }
        state.descendants = 0;
        ProcessTerminalEvidenceV1::new(
            binding,
            ProcessTerminalDispositionV1::Terminated,
            state.owner_verification,
            state.tree_cleanup,
            [3; 32],
        )
    }
}

impl ProcessControlPortV1 for VirtualProcessTreeFixtureV1 {
    fn request_graceful(
        &self,
        binding: &ProcessLifecycleBindingV1,
    ) -> Result<(), ProcessPlatformFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProcessPlatformFailure::ProcessUncertain)?;
        state.calls.push(VirtualProcessCallV1::RequestGraceful);
        if state.graceful_rejected {
            return Err(ProcessPlatformFailure::TerminationUnverified);
        }
        (state.held_binding.as_ref() == Some(binding))
            .then_some(())
            .ok_or(ProcessPlatformFailure::LifecycleControlMismatch)
    }

    fn wait_for_grace(
        &self,
        binding: &ProcessLifecycleBindingV1,
        _: MonotonicDeadline,
    ) -> Result<Option<ProcessTerminalEvidenceV1>, ProcessPlatformFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProcessPlatformFailure::ProcessUncertain)?;
        state.calls.push(VirtualProcessCallV1::WaitForGrace);
        if state.held_binding.as_ref() != Some(binding) {
            return Err(ProcessPlatformFailure::LifecycleControlMismatch);
        }
        match state.grace {
            VirtualGraceScriptV1::Complete => {
                state.descendants = 0;
                Ok(Some(ProcessTerminalEvidenceV1::new(
                    binding,
                    ProcessTerminalDispositionV1::Completed,
                    state.owner_verification,
                    state.tree_cleanup,
                    [4; 32],
                )?))
            }
            VirtualGraceScriptV1::Expire => Ok(None),
            VirtualGraceScriptV1::Ambiguous => Err(ProcessPlatformFailure::TerminationUnverified),
        }
    }

    fn observe_terminal(
        &self,
        binding: &ProcessLifecycleBindingV1,
        _: MonotonicDeadline,
    ) -> Result<Option<ProcessTerminalEvidenceV1>, ProcessPlatformFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProcessPlatformFailure::ProcessUncertain)?;
        state.calls.push(VirtualProcessCallV1::ObserveTerminal);
        if state.held_binding.as_ref() != Some(binding) {
            return Err(ProcessPlatformFailure::LifecycleControlMismatch);
        }
        match state.completion {
            VirtualCompletionScriptV1::Pending => Ok(None),
            VirtualCompletionScriptV1::Complete => Ok(Some(ProcessTerminalEvidenceV1::new(
                binding,
                ProcessTerminalDispositionV1::Completed,
                runne_platform_ports::process::ProcessOwnerVerificationV1::Verified,
                runne_platform_ports::process::ProcessTreeCleanupV1::Verified,
                [5; 32],
            )?)),
            VirtualCompletionScriptV1::Mismatch => Ok(Some(ProcessTerminalEvidenceV1::new(
                binding,
                ProcessTerminalDispositionV1::Completed,
                state.owner_verification,
                state.tree_cleanup,
                [5; 32],
            )?)),
            VirtualCompletionScriptV1::Unavailable => {
                Err(ProcessPlatformFailure::TerminationUnverified)
            }
        }
    }
}
