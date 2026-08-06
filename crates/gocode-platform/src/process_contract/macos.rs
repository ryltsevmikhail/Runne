//! macOS fail-closed process platform stub.

use gocode_platform_ports::process::{
    MonotonicDeadline, ProcessLaunchOutcomeV1, ProcessLifecycleBindingV1, ProcessPlatformFailure,
    ProcessPlatformPort, ProcessPlatformRequestV1, ProcessStubDisposition,
    ProcessTerminalEvidenceV1,
};

/// macOS process platform stub that rejects every operation before an OS boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacOsProcessPlatformPort;

impl ProcessPlatformPort for MacOsProcessPlatformPort {
    type Prepared = ();

    fn validate_and_prepare(
        &self,
        _request: &ProcessPlatformRequestV1,
        _deadline: MonotonicDeadline,
    ) -> Result<Self::Prepared, ProcessPlatformFailure> {
        Err(ProcessPlatformFailure::Disposition(
            ProcessStubDisposition::NotQualified,
        ))
    }

    fn launch(
        &self,
        _prepared: Self::Prepared,
        _binding: &ProcessLifecycleBindingV1,
        _deadline: MonotonicDeadline,
    ) -> Result<ProcessLaunchOutcomeV1, ProcessPlatformFailure> {
        Err(ProcessPlatformFailure::Disposition(
            ProcessStubDisposition::NotQualified,
        ))
    }

    fn terminate(
        &self,
        _binding: &ProcessLifecycleBindingV1,
        _deadline: MonotonicDeadline,
    ) -> Result<ProcessTerminalEvidenceV1, ProcessPlatformFailure> {
        Err(ProcessPlatformFailure::Disposition(
            ProcessStubDisposition::NotQualified,
        ))
    }
}
