/// Exact runtime, Store lineage, subject, launch and command binding shared by every phase.
/// Callers clip expiry to session/challenge/mode limits and reuse it on retries.
#[derive(Clone, PartialEq, Eq)]
pub struct PermissionControlContextV1 {
    pub runtime_authority: String,
    pub store_lineage_id: [u8; 16],
    pub stable_subject_digest: [u8; 32],
    pub protected_launch_authority_id: [u8; 16],
    pub desktop_authority_id: [u8; 16],
    pub daemon_instance_id: [u8; 16],
    pub protected_session_id: [u8; 16],
    pub launch_generation: u64,
    pub native_key_epoch: u64,
    pub command_id: [u8; 16],
    pub idempotency_key: String,
    pub public_request_digest: [u8; 32],
    pub predecessor_transcript_digest: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}
