pub(super) const MAX_DRAFT_BYTES: usize = 64 * 1024;
pub(super) const MAX_DRAFT_PAYLOAD_BYTES: i64 = 65_600;
// Counts every durable scope row, including tombstones; slots are never reclaimed.
pub(super) const MAX_DRAFT_SLOTS: i64 = 128;
pub(super) const MAX_DRAFT_REVISION: u64 = 9_007_199_254_740_991;
pub(super) const MAGIC: &[u8; 8] = b"RNDRAFT1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedDraftScope {
    pub lineage: String,
    pub authority: String,
    pub principal: String,
    pub project_id: String,
    pub workspace_id: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedDraft {
    pub revision: u64,
    pub prompt: Option<String>,
    pub scope_token: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtectedDraftError {
    #[error("protected draft storage is unavailable")]
    Unavailable,
    #[error("protected draft revision changed")]
    Conflict,
    #[error("protected draft scope changed")]
    ScopeMismatch,
    #[error("protected draft capacity reached")]
    Capacity,
    #[error("protected draft data is invalid")]
    Invalid,
    #[error("protected draft storage failed")]
    Storage,
}
