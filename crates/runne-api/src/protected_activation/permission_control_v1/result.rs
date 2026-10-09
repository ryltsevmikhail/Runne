#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PermissionControlResultCodeV1 {
    Pending,
    Committed,
    Cancelled,
    Expired,
    Invalidated,
    Denied,
}

/// Safe canonical readback. A committed result must carry a coherent receipt and revisions.
#[derive(Clone, PartialEq, Eq)]
pub struct PermissionControlResultV1 {
    pub code: PermissionControlResultCodeV1,
    pub command_id: [u8; 16],
    pub public_request_digest: [u8; 32],
    pub receipt_digest: Option<[u8; 32]>,
    pub authorization_revision: Option<u64>,
    pub managed_policy_revision: Option<u64>,
}
