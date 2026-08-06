//! Exact lifecycle control contract with no identifier-only operations.

use gocode_platform_ports::process::{
    MonotonicDeadline, ProcessLifecycleBindingV1, ProcessPlatformFailure, ProcessTerminalEvidenceV1,
};

/// Exact graceful-control boundary for an already launched held process tree.
pub(crate) trait ProcessControlPortV1: Send + Sync {
    /// Requests graceful shutdown of the exact held tree.
    ///
    /// # Errors
    ///
    /// Returns a closed failure if exact control cannot be established.
    fn request_graceful(
        &self,
        binding: &ProcessLifecycleBindingV1,
    ) -> Result<(), ProcessPlatformFailure>;

    /// Waits only until the supplied monotonic grace deadline.
    ///
    /// `Ok(None)` means grace elapsed and forced tree termination is required.
    ///
    /// # Errors
    ///
    /// Returns a closed failure if terminal evidence cannot be established.
    fn wait_for_grace(
        &self,
        binding: &ProcessLifecycleBindingV1,
        deadline: MonotonicDeadline,
    ) -> Result<Option<ProcessTerminalEvidenceV1>, ProcessPlatformFailure>;

    /// Observes terminal evidence for the exact held tree without launching it.
    ///
    /// # Errors
    ///
    /// Returns a closed failure if exact terminal evidence cannot be observed.
    fn observe_terminal(
        &self,
        binding: &ProcessLifecycleBindingV1,
        deadline: MonotonicDeadline,
    ) -> Result<Option<ProcessTerminalEvidenceV1>, ProcessPlatformFailure>;
}
