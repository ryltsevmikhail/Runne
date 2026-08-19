//! Explicit target selection for fail-closed process platform stubs.

use super::{LinuxProcessPlatformPort, MacOsProcessPlatformPort, WindowsProcessPlatformPort};
use runne_platform_ports::process::{
    MonotonicDeadline, ProcessLaunchOutcomeV1, ProcessLifecycleBindingV1, ProcessPlatformFailure,
    ProcessPlatformPort, ProcessPlatformRequestV1, ProcessStubDisposition,
    ProcessTerminalEvidenceV1,
};

/// Closed process-platform target selection without runtime host detection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessPlatformTargetV1 {
    /// Linux target.
    Linux,
    /// macOS target.
    Macos,
    /// Windows target.
    Windows,
    /// Explicitly unsupported target.
    Other,
}

/// Explicit target-selected process platform stub.
#[derive(Clone, Copy, Debug)]
pub enum ProcessPlatformStubV1 {
    /// Linux fail-closed stub.
    Linux(LinuxProcessPlatformPort),
    /// macOS fail-closed stub.
    Macos(MacOsProcessPlatformPort),
    /// Windows fail-closed stub.
    Windows(WindowsProcessPlatformPort),
    /// Explicit unsupported-target stub.
    Unsupported(UnsupportedProcessPlatformPort),
}

impl ProcessPlatformStubV1 {
    /// Returns the fail-closed stub named by the supplied target.
    #[must_use]
    pub const fn for_target(target: ProcessPlatformTargetV1) -> Self {
        match target {
            ProcessPlatformTargetV1::Linux => Self::Linux(LinuxProcessPlatformPort),
            ProcessPlatformTargetV1::Macos => Self::Macos(MacOsProcessPlatformPort),
            ProcessPlatformTargetV1::Windows => Self::Windows(WindowsProcessPlatformPort),
            ProcessPlatformTargetV1::Other => Self::Unsupported(UnsupportedProcessPlatformPort),
        }
    }
}

impl ProcessPlatformPort for ProcessPlatformStubV1 {
    type Prepared = ();

    fn validate_and_prepare(
        &self,
        request: &ProcessPlatformRequestV1,
        deadline: MonotonicDeadline,
    ) -> Result<Self::Prepared, ProcessPlatformFailure> {
        match self {
            Self::Linux(port) => port.validate_and_prepare(request, deadline),
            Self::Macos(port) => port.validate_and_prepare(request, deadline),
            Self::Windows(port) => port.validate_and_prepare(request, deadline),
            Self::Unsupported(port) => port.validate_and_prepare(request, deadline),
        }
    }

    fn launch(
        &self,
        prepared: Self::Prepared,
        binding: &ProcessLifecycleBindingV1,
        deadline: MonotonicDeadline,
    ) -> Result<ProcessLaunchOutcomeV1, ProcessPlatformFailure> {
        match self {
            Self::Linux(port) => port.launch(prepared, binding, deadline),
            Self::Macos(port) => port.launch(prepared, binding, deadline),
            Self::Windows(port) => port.launch(prepared, binding, deadline),
            Self::Unsupported(port) => port.launch(prepared, binding, deadline),
        }
    }

    fn terminate(
        &self,
        binding: &ProcessLifecycleBindingV1,
        deadline: MonotonicDeadline,
    ) -> Result<ProcessTerminalEvidenceV1, ProcessPlatformFailure> {
        match self {
            Self::Linux(port) => port.terminate(binding, deadline),
            Self::Macos(port) => port.terminate(binding, deadline),
            Self::Windows(port) => port.terminate(binding, deadline),
            Self::Unsupported(port) => port.terminate(binding, deadline),
        }
    }
}

/// Unsupported-target process platform stub that rejects before input use.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedProcessPlatformPort;

impl ProcessPlatformPort for UnsupportedProcessPlatformPort {
    type Prepared = ();

    fn validate_and_prepare(
        &self,
        _request: &ProcessPlatformRequestV1,
        _deadline: MonotonicDeadline,
    ) -> Result<Self::Prepared, ProcessPlatformFailure> {
        Err(ProcessPlatformFailure::Disposition(
            ProcessStubDisposition::Unsupported,
        ))
    }

    fn launch(
        &self,
        _prepared: Self::Prepared,
        _binding: &ProcessLifecycleBindingV1,
        _deadline: MonotonicDeadline,
    ) -> Result<ProcessLaunchOutcomeV1, ProcessPlatformFailure> {
        Err(ProcessPlatformFailure::Disposition(
            ProcessStubDisposition::Unsupported,
        ))
    }

    fn terminate(
        &self,
        _binding: &ProcessLifecycleBindingV1,
        _deadline: MonotonicDeadline,
    ) -> Result<ProcessTerminalEvidenceV1, ProcessPlatformFailure> {
        Err(ProcessPlatformFailure::Disposition(
            ProcessStubDisposition::Unsupported,
        ))
    }
}
