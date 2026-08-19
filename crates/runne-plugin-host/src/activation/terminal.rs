/// Opaque terminal evidence issued by a certified backend.
#[derive(Debug)]
pub struct PluginTerminalEvidence {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    reservation: [u8; 32],
}

impl PluginTerminalEvidence {
    fn matches(&self, snapshot: &PluginActivationSnapshot) -> bool {
        self.activation_id == snapshot.activation_id
            && self.package_digest == snapshot.package_digest
            && self.generation == snapshot.generation
            && snapshot
                .start_intent
                .as_ref()
                .is_some_and(|intent| self.reservation == *intent.reservation())
    }

    #[cfg(test)]
    pub(crate) fn certified(snapshot: &PluginActivationSnapshot) -> Self {
        Self {
            activation_id: snapshot.activation_id.clone(),
            package_digest: snapshot.package_digest,
            generation: snapshot.generation,
            reservation: *snapshot
                .start_intent
                .as_ref()
                .expect("certified terminal evidence requires a start intent")
                .reservation(),
        }
    }

    #[cfg(test)]
    pub(crate) fn certified_process(lease: &PluginProcessLease) -> Self {
        Self {
            activation_id: lease.activation_id().clone(),
            package_digest: lease.package_digest(),
            generation: lease.generation(),
            reservation: *lease.reservation(),
        }
    }
}

/// Invalid activation lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginLifecycleError {
    InvalidTransition,
    InvalidTerminalEvidence,
    InvalidBackendEvidence,
    BackendUnavailable,
}
