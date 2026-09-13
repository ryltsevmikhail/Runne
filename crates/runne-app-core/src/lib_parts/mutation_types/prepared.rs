/// Opaque prepared mutation. It is one-shot because anchored state carries the
/// command identity and the dispatching transition accepts it only once.
pub struct PreparedMutationLease {
    runtime_identity: replay::StableRuntimeIdentity,
    gate_epoch: u64,
    anchored_record: runne_local_store::MutationRecord,
    request: MutationRequest,
    finalized_root: Option<FinalizedRootAdmission>,
}

/// One-shot root binding frozen at preparation. It cannot be recreated from an
/// ordinary decoded claim and is never exposed outside the coordinator.
struct FinalizedRootAdmission {
    admission: runne_runtime_client::ProtectedRootAdmission,
    runtime_identity: replay::StableRuntimeIdentity,
    workspace_id: CanonicalId,
    expected_version: u64,
    admission_digest: [u8; 32],
}

/// Move-only neutral host handoff for the bind-then-optional-open workspace mutation.
/// It intentionally carries no platform path, handle, renderer reference, or
/// transport token.
pub struct PreparedWorkspaceOpen {
    bind: PreparedMutationLease,
    open: Option<PreparedMutationLease>,
    possible_send: bool,
}

impl std::fmt::Debug for PreparedWorkspaceOpen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedWorkspaceOpen(<redacted>)")
    }
}

impl PreparedWorkspaceOpen {
    pub(crate) const fn parts_and_possible_send_mut(
        &mut self,
    ) -> (
        &mut PreparedMutationLease,
        Option<&mut PreparedMutationLease>,
        &mut bool,
    ) {
        (&mut self.bind, self.open.as_mut(), &mut self.possible_send)
    }
}

impl std::fmt::Debug for PreparedMutationLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedMutationLease(<redacted>)")
    }
}

/// Authenticated, redacted runtime binding for host-only consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationAdmissionBinding {
    pub runtime_identity_digest: [u8; 32],
    pub principal_digest: [u8; 32],
    pub gate_epoch: u64,
}
