use subtle::ConstantTimeEq;

use crate::canonical::RuntimeSessionAuthority;
use gocode_api::{
    ReplayRetentionBaselineWireV1, UnauthenticatedReplayRetentionBaselineFieldsV1,
    validate_unauthenticated_replay_retention_baseline,
};

/// Verification failure for an untrusted replay-retention baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayBaselineVerificationError {
    Unauthorized,
}

/// Authenticated, redacted retention baseline. It is only constructed by the
/// private runtime session authority verifier.
///
/// ```compile_fail
/// use gocode_runtime_client::ReplayRetentionBaselineV1;
/// let _ = ReplayRetentionBaselineV1 { fields: unreachable!() };
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct ReplayRetentionBaselineV1 {
    fields: UnauthenticatedReplayRetentionBaselineFieldsV1,
}

#[allow(clippy::must_use_candidate)]
impl ReplayRetentionBaselineV1 {
    /// Bound runtime authority identity.
    pub const fn authority_id(&self) -> &[u8; 16] {
        &self.fields.authority_id
    }
    /// Bound authenticated principal.
    pub fn principal_id(&self) -> &str {
        &self.fields.principal_id
    }
    /// Bound event-log lineage.
    pub const fn lineage_id(&self) -> &[u8; 16] {
        &self.fields.lineage_id
    }
    /// Exact authenticated runtime-session binding digest.
    pub const fn runtime_session_binding_digest(&self) -> &[u8; 32] {
        &self.fields.runtime_session_binding_digest
    }
    /// Exact authenticated replay scope digest.
    pub const fn replay_scope_digest(&self) -> &[u8; 32] {
        &self.fields.replay_scope_digest
    }
    /// Exact aggregate kind after authentication.
    pub const fn aggregate_kind(&self) -> gocode_api::ApiReplayAggregateKind {
        self.fields.aggregate_kind
    }
    /// Exact aggregate identity after authentication.
    pub const fn aggregate_id(&self) -> &[u8; 16] {
        &self.fields.aggregate_id
    }
    /// Closed projection bytes, authenticated but not restored as a live aggregate.
    pub fn projection_bytes(&self) -> &[u8] {
        &self.fields.projection_bytes
    }
    /// Closed projection codec identifier.
    pub const fn projection_codec(&self) -> u8 {
        self.fields.projection_codec
    }
    /// Recomputed closed projection digest.
    pub const fn projection_digest(&self) -> &[u8; 32] {
        &self.fields.projection_digest
    }
    /// Aggregate-local baseline sequence and version (equal and positive).
    pub const fn sequence(&self) -> u64 {
        self.fields.sequence
    }
    /// Aggregate version equal to the authenticated sequence.
    pub const fn version(&self) -> u64 {
        self.fields.version
    }
    /// Global log position of the complete baseline projection.
    pub const fn baseline_global_position(&self) -> i64 {
        self.fields.baseline_global_position
    }
    /// Retention floor captured atomically with the baseline.
    pub const fn retained_floor(&self) -> i64 {
        self.fields.retained_floor
    }
    /// Captured global high water.
    pub const fn captured_high_water(&self) -> i64 {
        self.fields.captured_high_water
    }
    /// Positive authenticated retention generation.
    pub const fn retention_generation(&self) -> u64 {
        self.fields.retention_generation
    }
    /// Opaque authenticated retention witness.
    pub const fn retention_witness(&self) -> &[u8; 32] {
        &self.fields.retention_witness
    }
    /// Authenticated Unix-millisecond issuance instant.
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.fields.issued_at_unix_ms
    }
    /// Authenticated Unix-millisecond expiry instant.
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.fields.expires_at_unix_ms
    }
}

impl std::fmt::Debug for ReplayRetentionBaselineV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayRetentionBaselineV1")
            .field("aggregate_kind", &self.fields.aggregate_kind)
            .field("redacted", &true)
            .finish()
    }
}

impl RuntimeSessionAuthority {
    #[allow(dead_code)] // consumed by the replay HTTP parser in the next wire slice
    pub(crate) fn verify_replay_retention_baseline(
        &self,
        wire: &ReplayRetentionBaselineWireV1,
        scope: super::ReplayScope,
        now_unix_ms: u64,
    ) -> Result<ReplayRetentionBaselineV1, ReplayBaselineVerificationError> {
        let Some(binding) = self.replay_binding() else {
            return Err(ReplayBaselineVerificationError::Unauthorized);
        };
        let fields = wire.to_unauthenticated_fields();
        let stable = binding.stable();
        if fields.authority_id != *stable.authority_id()
            || fields.principal_id != stable.principal_id().as_str()
            || fields.lineage_id != *stable.lineage_id().as_bytes()
            || fields.runtime_session_binding_digest != binding.canonical_digest()
            || fields.replay_scope_digest != replay_scope_digest(scope)
            || fields.issued_at_unix_ms > now_unix_ms
            || now_unix_ms >= fields.expires_at_unix_ms
        {
            return Err(ReplayBaselineVerificationError::Unauthorized);
        }
        let expected = self.replay_baseline_mac(fields.runtime_session_binding_digest, wire);
        if !bool::from(expected.ct_eq(&fields.witness_mac))
            || validate_unauthenticated_replay_retention_baseline(
                wire,
                api_aggregate_kind(scope),
                &canonical_id_bytes(scope.aggregate_id()),
            )
            .is_err()
        {
            return Err(ReplayBaselineVerificationError::Unauthorized);
        }
        Ok(ReplayRetentionBaselineV1 { fields })
    }
}

const fn api_aggregate_kind(scope: super::ReplayScope) -> gocode_api::ApiReplayAggregateKind {
    match scope.aggregate_kind() {
        super::ReplayAggregateKind::Conversation => {
            gocode_api::ApiReplayAggregateKind::Conversation
        }
        super::ReplayAggregateKind::TaskRun => gocode_api::ApiReplayAggregateKind::TaskRun,
    }
}

fn canonical_id_bytes(id: super::CanonicalId) -> [u8; 16] {
    *uuid::Uuid::parse_str(&id.to_string())
        .expect("CanonicalId always formats as UUID")
        .as_bytes()
}

fn replay_scope_digest(scope: super::ReplayScope) -> [u8; 32] {
    gocode_api::canonical_aggregate_replay_scope_digest(
        api_aggregate_kind(scope),
        &canonical_id_bytes(scope.aggregate_id()),
    )
}

include!("baseline_v2_client.rs");
