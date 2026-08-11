impl DirectorySelectionManager {
    /// Revokes every host-retained native value before runtime shutdown waits.
    pub(crate) fn clear_pending_authority(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.selections.clear();
            state.prepared.clear();
            state.reservations.clear();
        }
    }
}
