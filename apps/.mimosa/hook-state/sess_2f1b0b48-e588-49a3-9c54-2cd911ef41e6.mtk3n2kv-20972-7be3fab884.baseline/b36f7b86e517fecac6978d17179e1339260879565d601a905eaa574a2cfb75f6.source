#[allow(dead_code)]
impl DirectorySelectionManager {
    /// Atomically fences a window and removes all of its pending selections.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid labels, poisoned state, or overflow.
    fn invalidate_window(&self, window: &str) -> Result<(), SelectionError> {
        self.state
            .lock()
            .map_err(|_| SelectionError)?
            .advance(window)
            .map(|_| ())
            .map_err(|_| SelectionError)
    }

    /// Issues a deterministic reference for collision tests only.
    ///
    /// # Errors
    ///
    /// Returns the same closed validation errors as [`Self::issue`].
    fn issue_with_reference_for_test(
        &self,
        window: &str,
        expected_generation: u64,
        request: &str,
        root: VerifiedRootHandle,
        now: Instant,
        reference: String,
    ) -> Result<DirectorySelectionRef, SelectionError> {
        self.issue_inner(
            window,
            expected_generation,
            request,
            root,
            now,
            Some(reference),
        )
    }

    /// Deliberately poisons the shared state for fail-closed tests.
    fn poison_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _lock = self.state.lock().expect("state lock");
            panic!("test mutex poison");
        }));
    }

}
