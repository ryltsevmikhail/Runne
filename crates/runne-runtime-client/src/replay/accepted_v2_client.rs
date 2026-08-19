use base64::Engine as _;

/// Redacted common capability for a current V18 promotion accepted during
/// replay resume. Its semantic projection is authenticated by the native TCB.
#[derive(Clone, Eq, PartialEq)]
pub struct ReplayAcceptedPromotionV2 {
    capability: runne_api::replay::AuthenticatedAcceptedReplayProjectionV2,
}

impl ReplayAcceptedPromotionV2 {
    #[must_use]
    pub const fn capability(&self) -> &runne_api::replay::AuthenticatedAcceptedReplayProjectionV2 {
        &self.capability
    }
    #[must_use]
    pub const fn projection(
        &self,
    ) -> &runne_api::replay::promotion_projection::ReplayPromotionProjectionViewV1 {
        self.capability.promotion_view()
    }
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        self.capability.digest()
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.capability.sequence()
    }
    #[must_use]
    pub const fn global_position(&self) -> i64 {
        self.capability.global_position()
    }
    #[must_use]
    pub const fn head_event_id(&self) -> &[u8; 16] {
        self.capability.head_event_id()
    }
    #[must_use]
    pub const fn head_integrity_digest(&self) -> &[u8; 32] {
        self.capability.head_integrity_digest()
    }
    #[must_use]
    pub const fn captured_high_water(&self) -> i64 {
        self.capability.captured_high_water()
    }
}

pub struct ParsedAcceptedPromotionV2(runne_api::replay::UnauthenticatedAcceptedReplayProjectionV2);

impl ParsedAcceptedPromotionV2 {
    pub(super) fn decode(
        wire: super::wire::AcceptedPromotionWire,
    ) -> Result<Self, super::ReplayClientError> {
        let invalid =
            || super::ReplayClientError::new(super::ReplayClientErrorKind::InvalidResponse);
        let digest = super::validation::decode_lower_hex::<32>(&wire.projection_digest)
            .ok_or_else(invalid)?;
        let event_id =
            super::validation::decode_lower_hex::<16>(&wire.head_event_id).ok_or_else(invalid)?;
        let head = super::validation::decode_lower_hex::<32>(&wire.head_integrity_digest)
            .ok_or_else(invalid)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(wire.projection_bytes)
            .map_err(|_| invalid())?;
        let projection = runne_api::UnauthenticatedReplayPromotionProjectionV1::decode(&bytes)
            .map_err(|_| invalid())?;
        runne_api::replay::UnauthenticatedAcceptedReplayProjectionV2::new(
            projection,
            runne_api::replay::UnauthenticatedAcceptedReplayProjectionFactsV2 {
                codec: wire.codec,
                digest,
                sequence: wire.sequence,
                version: wire.version,
                global_position: wire.global_position,
                head_event_id: event_id,
                head_integrity_digest: head,
                captured_high_water: wire.captured_high_water,
            },
        )
        .map(Self)
        .map_err(|_| invalid())
    }

    pub(super) fn authenticate(
        self,
        authority: &crate::canonical::RuntimeSessionAuthority,
        baseline: &super::ReplayRetentionBaselineV2,
        suffix: super::resume::AppliedSuffix,
    ) -> Result<ReplayAcceptedPromotionV2, super::ReplayClientError> {
        let invalid =
            || super::ReplayClientError::new(super::ReplayClientErrorKind::InvalidResponse);
        let proof = match (suffix.cursor, suffix.last_event) {
            (None, None) => runne_api::replay::ReplayAcceptedSuffixProofV2::Empty,
            (Some(cursor), Some((event_id, integrity_digest, sequence, global_position))) => {
                runne_api::replay::ReplayAcceptedSuffixProofV2::LastEvent {
                    event_id,
                    integrity_digest,
                    sequence,
                    global_position,
                    cursor: cursor.0,
                }
            }
            _ => return Err(invalid()),
        };
        let verifier = authority
            .replay_baseline_v2_authenticator()
            .map_err(|()| invalid())?;
        verifier
            .authenticate_accepted_projection_v2(baseline.authenticated_capability(), self.0, proof)
            .map(|capability| ReplayAcceptedPromotionV2 { capability })
            .map_err(|_| invalid())
    }
}

impl std::fmt::Debug for ReplayAcceptedPromotionV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayAcceptedPromotionV2")
            .field("sequence", &self.sequence())
            .field("redacted", &true)
            .finish()
    }
}
