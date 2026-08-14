impl PreparedWorkspaceManager {
    pub(crate) fn begin_initial(
        &self, reference: &PreparedWorkspaceRef, window: &str, expected_generation: u64,
        request: &str, now: Instant, lifecycle: &crate::RuntimeLifecycleManager,
    ) -> Result<PreparedWorkspaceOpenAttempt, SelectionError> {
        self.begin_open(reference, window, expected_generation, request, now, PreparedWorkspacePhase::Ready,
            lifecycle.native_root_reaper().ok_or(SelectionError)?)
    }

    pub(crate) fn begin_retry(
        &self, reference: &PreparedWorkspaceRef, window: &str, expected_generation: u64,
        request: &str, now: Instant, lifecycle: &crate::RuntimeLifecycleManager,
    ) -> Result<PreparedWorkspaceOpenAttempt, SelectionError> {
        self.begin_open(reference, window, expected_generation, request, now, PreparedWorkspacePhase::Retained,
            lifecycle.native_root_reaper().ok_or(SelectionError)?)
    }

    #[cfg(all(test, feature = "test-support"))]
    pub(crate) fn consume_for_open(
        &self,
        reference: &PreparedWorkspaceRef,
        window: &str,
        expected_generation: u64,
        request: &str,
        now: Instant,
        lifecycle: &crate::RuntimeLifecycleManager,
    ) -> Result<PreparedWorkspaceOpenAttempt, SelectionError> {
        self.begin_initial(reference, window, expected_generation, request, now, lifecycle)
    }
}
