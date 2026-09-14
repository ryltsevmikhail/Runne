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
