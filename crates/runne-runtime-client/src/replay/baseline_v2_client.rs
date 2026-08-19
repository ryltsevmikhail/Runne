#[derive(Clone, Eq, PartialEq)]
pub struct ReplayRetentionBaselineV2 {
    fields: runne_api::UnauthenticatedReplayRetentionBaselineFieldsV2,
    authenticated: runne_api::replay::AuthenticatedReplayBaselineV2,
}
impl ReplayRetentionBaselineV2 {
    /// Borrows the verified native capability for the local persistence TCB.
    /// It exposes semantic evidence only; witness bytes remain private.
    #[must_use]
    pub const fn authenticated_capability(
        &self,
    ) -> &runne_api::replay::AuthenticatedReplayBaselineV2 {
        &self.authenticated
    }
    #[must_use]
    pub const fn authority_id(&self) -> &[u8; 16] {
        &self.fields.authority_id
    }
    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.fields.principal_id
    }
    #[must_use]
    pub const fn lineage_id(&self) -> &[u8; 16] {
        &self.fields.lineage_id
    }
    #[must_use]
    pub const fn runtime_session_binding_digest(&self) -> &[u8; 32] {
        &self.fields.runtime_session_binding_digest
    }
    #[must_use]
    pub const fn replay_scope_digest(&self) -> &[u8; 32] {
        &self.fields.replay_scope_digest
    }
    #[must_use]
    pub const fn aggregate_kind(&self) -> runne_api::ApiReplayAggregateKind {
        self.fields.aggregate_kind
    }
    #[must_use]
    pub const fn aggregate_id(&self) -> &[u8; 16] {
        &self.fields.aggregate_id
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.fields.sequence
    }
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.fields.version
    }
    #[must_use]
    pub const fn baseline_global_position(&self) -> i64 {
        self.fields.baseline_global_position
    }
    #[must_use]
    pub const fn head_event_id(&self) -> &[u8; 16] {
        &self.fields.head_event_id
    }
    #[must_use]
    pub const fn head_integrity_digest(&self) -> &[u8; 32] {
        &self.fields.head_integrity_digest
    }
    #[must_use]
    pub const fn retained_floor(&self) -> i64 {
        self.fields.retained_floor
    }
    #[must_use]
    pub const fn captured_high_water(&self) -> i64 {
        self.fields.captured_high_water
    }
    #[must_use]
    pub const fn retention_generation(&self) -> u64 {
        self.fields.retention_generation
    }
    #[must_use]
    pub const fn retention_manifest_digest(&self) -> &[u8; 32] {
        &self.fields.retention_manifest_digest
    }
    #[must_use]
    pub const fn promotion_codec(&self) -> u8 {
        self.fields.promotion_codec
    }
    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.fields.issued_at_unix_ms
    }
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.fields.expires_at_unix_ms
    }
    #[must_use]
    pub fn promotion_projection(
        &self,
    ) -> Option<runne_api::UnauthenticatedReplayPromotionProjectionV1> {
        runne_api::UnauthenticatedReplayPromotionProjectionV1::decode(
            &self.fields.promotion_projection_bytes,
        )
        .ok()
    }
    pub(super) fn resume_wire(
        &self,
        scope: super::ReplayScope,
    ) -> Option<runne_api::ReplayRetentionBaselineWireV2> {
        (self.fields.aggregate_kind == api_aggregate_kind(scope)
            && self.fields.aggregate_id == canonical_id_bytes(scope.aggregate_id()))
        .then(|| {
            runne_api::ReplayRetentionBaselineWireV2::from_unauthenticated_fields(
                self.fields.clone(),
            )
        })
    }
}
impl std::fmt::Debug for ReplayRetentionBaselineV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayRetentionBaselineV2")
            .field("redacted", &true)
            .finish()
    }
}
impl RuntimeSessionAuthority {
    pub(crate) fn verify_replay_retention_baseline_v2(
        &self,
        wire: &runne_api::ReplayRetentionBaselineWireV2,
        scope: super::ReplayScope,
        now: u64,
    ) -> Result<ReplayRetentionBaselineV2, ReplayBaselineVerificationError> {
        let fields = wire.to_unauthenticated_fields();
        let verifier = self
            .replay_baseline_v2_authenticator()
            .map_err(|()| ReplayBaselineVerificationError::Unauthorized)?;
        let authenticated = verifier.verify_wire_v2(
            wire, api_aggregate_kind(scope), canonical_id_bytes(scope.aggregate_id()), now,
        ).map_err(|_| ReplayBaselineVerificationError::Unauthorized)?;
        Ok(ReplayRetentionBaselineV2 { fields, authenticated })
    }
}
