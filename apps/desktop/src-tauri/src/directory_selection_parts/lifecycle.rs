impl DirectorySelectionManager {
    /// Revokes every host-retained native value before runtime shutdown waits.
    pub(super) fn clear_pending_authority(&self) {
        let pending = self.state.lock().map_or_else(|_| Vec::new(), |mut state| {
            state.selections.clear();
            let mut attempts = std::collections::HashMap::new();
            let pending = std::mem::take(&mut state.prepared)
                .into_iter()
                .filter_map(|(reference, mut entry)| match entry.phase {
                    crate::prepared_workspace::PreparedWorkspacePhase::Attempting { attempt_id, .. } => {
                        entry.phase = crate::prepared_workspace::PreparedWorkspacePhase::Attempting { attempt_id, revoked: true };
                        attempts.insert(reference, entry);
                        None
                    }
                    _ => Some(entry),
                })
                .collect::<Vec<_>>();
            state.prepared = attempts;
            state.reservations.clear();
            pending
        });
        drop(pending);
    }
}
