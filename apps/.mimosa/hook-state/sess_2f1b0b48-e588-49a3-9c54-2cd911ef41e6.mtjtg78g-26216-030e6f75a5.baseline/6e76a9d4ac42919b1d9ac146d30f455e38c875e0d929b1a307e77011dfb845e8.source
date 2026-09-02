impl PreparedWorkspaceManager {
    pub(crate) fn retained_for_test(&self, reference: &PreparedWorkspaceRef) -> bool {
        self.state
            .lock()
            .expect("state lock")
            .prepared
            .get(&reference.0)
            .is_some_and(|entry| entry.phase == PreparedWorkspacePhase::Retained)
    }

    pub(crate) fn has_authority_for_test(&self, reference: &PreparedWorkspaceRef) -> bool {
        self.state
            .lock()
            .expect("state lock")
            .prepared
            .get(&reference.0)
            .is_some_and(|entry| {
                entry.root.is_some()
                    || entry.admission.is_some()
                    || entry.operation_permit.is_some()
                    || entry.prepared_open.is_some()
            })
    }

    pub(crate) fn orphaned_for_test(&self, reference: &PreparedWorkspaceRef) -> bool {
        self.state
            .lock()
            .expect("state lock")
            .prepared
            .get(&reference.0)
            .is_some_and(|entry| entry.phase == PreparedWorkspacePhase::Orphaned)
    }

    pub(crate) fn has_entry_for_test(&self, reference: &PreparedWorkspaceRef) -> bool {
        self.state.lock().expect("state lock").prepared.contains_key(&reference.0)
    }
}
