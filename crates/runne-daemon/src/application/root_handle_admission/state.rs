struct State {
    leases: usize,
    stopped: bool,
    pending: std::collections::HashMap<[u8; 16], Pending>,
    active: std::collections::HashMap<runne_domain::id::WorkspaceId, ActiveRoot>,
}

struct Pending {
    workspace: runne_domain::id::WorkspaceId,
    version: u64,
    identity: [u8; 32],
    offer_digest: [u8; 32],
    digest: [u8; 32],
    expires_at: u64,
    baseline: WorkspaceBaseline,
    _handle: VerifiedRootHandle,
}

struct ActiveRoot {
    version: u64,
    baseline: WorkspaceBaseline,
    handle: VerifiedRootHandle,
}

/// The admitted root stays current while the workspace lives at or past the
/// version it authorized: the bind itself advances the store past the
/// admitted `expected_version`, so strict equality would fence the handle the
/// attach flow just created. Re-binds replace the active root wholesale, and
/// session rotations fence it, so nothing stale can ever serve here.
pub(super) fn active_root_is_current(workspace_version: u64, admitted_version: u64) -> bool {
    workspace_version >= admitted_version
}
