/// Unauthenticated response facts parsed from the V2 resume endpoint.
///
/// This is intentionally not promotable until the session-bound authenticator
/// checks it against the original authenticated baseline and suffix proof.
#[derive(Clone, Eq, PartialEq)]
pub struct UnauthenticatedAcceptedReplayProjectionV2 {
    projection: UnauthenticatedReplayPromotionProjectionV1,
    codec: u8,
    digest: [u8; 32],
    sequence: u64,
    version: u64,
    global_position: i64,
    head_event_id: [u8; 16],
    head_integrity_digest: [u8; 32],
    captured_high_water: i64,
}

/// Fixed parsed fields belonging to one untrusted accepted-current response.
#[derive(Clone, Eq, PartialEq)]
pub struct UnauthenticatedAcceptedReplayProjectionFactsV2 {
    pub codec: u8,
    pub digest: [u8; 32],
    pub sequence: u64,
    pub version: u64,
    pub global_position: i64,
    pub head_event_id: [u8; 16],
    pub head_integrity_digest: [u8; 32],
    pub captured_high_water: i64,
}

/// Exact authenticated suffix boundary supplied by the V2 replay validator.
#[derive(Clone, Eq, PartialEq)]
pub enum ReplayAcceptedSuffixProofV2 {
    /// The baseline itself is the accepted current projection.
    Empty,
    /// The accepted head must equal the final verified suffix event.
    LastEvent {
        event_id: [u8; 16],
        integrity_digest: [u8; 32],
        sequence: u64,
        global_position: i64,
        cursor: String,
    },
}

/// Parsed, untrusted identity facts from the baseline checkpoint cursor.
#[derive(Clone, Eq, PartialEq)]
pub struct UnauthenticatedReplayBaselineCheckpointFactsV2 {
    pub cursor: String,
    pub aggregate_kind: ApiReplayAggregateKind,
    pub aggregate_id: [u8; 16],
    pub event_id: [u8; 16],
    pub sequence: u64,
    pub global_position: i64,
}

/// Opaque accepted-current projection authenticated for local promotion.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedAcceptedReplayProjectionV2 {
    projection: promotion_projection::ReplayPromotionProjectionViewV1,
    digest: [u8; 32],
    sequence: u64,
    global_position: i64,
    head_event_id: [u8; 16],
    head_integrity_digest: [u8; 32],
    captured_high_water: i64,
    baseline_evidence_digest: [u8; 32],
}

/// Session-bound server baseline checkpoint for the native persistence TCB.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedReplayBaselineCheckpointV2 {
    cursor: String,
    _verifier_tag: [u8; 32],
    baseline_evidence_digest: [u8; 32],
}

impl UnauthenticatedAcceptedReplayProjectionV2 {
    /// Builds a bounded, non-promotable parsed response value.
    pub fn new(
        projection: UnauthenticatedReplayPromotionProjectionV1,
        facts: UnauthenticatedAcceptedReplayProjectionFactsV2,
    ) -> Result<Self, ReplayBaselineV2AuthenticationError> {
        if facts.codec != 1
            || facts.digest == [0; 32]
            || facts.sequence == 0
            || facts.sequence != facts.version
            || facts.global_position <= 0
            || facts.global_position > facts.captured_high_water
            || facts.head_event_id == [0; 16]
            || facts.head_integrity_digest == [0; 32]
        {
            return Err(ReplayBaselineV2AuthenticationError::Unauthorized);
        }
        let actual = accepted_projection_digest(projection.view());
        (actual == &facts.digest)
            .then_some(Self {
                projection,
                codec: facts.codec,
                digest: facts.digest,
                sequence: facts.sequence,
                version: facts.version,
                global_position: facts.global_position,
                head_event_id: facts.head_event_id,
                head_integrity_digest: facts.head_integrity_digest,
                captured_high_water: facts.captured_high_water,
            })
            .ok_or(ReplayBaselineV2AuthenticationError::Unauthorized)
    }
}

impl ReplayBaselineV2Authenticator {
    /// Authenticates the exact baseline checkpoint returned by resume admission.
    pub fn authenticate_resume_checkpoint_v2(
        &self,
        baseline: &AuthenticatedReplayBaselineV2,
        facts: UnauthenticatedReplayBaselineCheckpointFactsV2,
    ) -> Result<AuthenticatedReplayBaselineCheckpointV2, ReplayBaselineV2AuthenticationError> {
        if facts.cursor.is_empty()
            || facts.cursor.len() > 4096
            || baseline.runtime_session_binding_digest() != &self.binding.canonical_digest()
            || !bool::from(baseline.verifier_tag.ct_eq(&self.verifier_tag()))
            || facts.aggregate_kind != baseline.aggregate_kind()
            || facts.aggregate_id != *baseline.aggregate_id()
            || facts.event_id != *baseline.head_event_id()
            || facts.sequence != baseline.sequence()
            || facts.global_position != baseline.baseline_global_position()
        {
            return Err(ReplayBaselineV2AuthenticationError::Unauthorized);
        }
        Ok(AuthenticatedReplayBaselineCheckpointV2 {
            cursor: facts.cursor,
            _verifier_tag: self.verifier_tag(),
            baseline_evidence_digest: baseline.local_evidence_digest(),
        })
    }

    /// Authenticates the V18 accepted current projection for a pending resume.
    pub fn authenticate_accepted_projection_v2(
        &self,
        baseline: &AuthenticatedReplayBaselineV2,
        accepted: UnauthenticatedAcceptedReplayProjectionV2,
        suffix: ReplayAcceptedSuffixProofV2,
    ) -> Result<AuthenticatedAcceptedReplayProjectionV2, ReplayBaselineV2AuthenticationError> {
        if baseline.runtime_session_binding_digest() != &self.binding.canonical_digest()
            || !bool::from(baseline.verifier_tag.ct_eq(&self.verifier_tag()))
        {
            return Err(ReplayBaselineV2AuthenticationError::Unauthorized);
        }
        let identity_matches = match accepted.projection.view() {
            promotion_projection::ReplayPromotionProjectionViewV1::Conversation(value) => {
                baseline.aggregate_kind() == ApiReplayAggregateKind::Conversation
                    && value.aggregate_id() == *baseline.aggregate_id()
            }
            promotion_projection::ReplayPromotionProjectionViewV1::TaskRun(value) => {
                baseline.aggregate_kind() == ApiReplayAggregateKind::TaskRun
                    && value.aggregate_id() == *baseline.aggregate_id()
            }
        };
        if !identity_matches
            || accepted.sequence < baseline.sequence()
            || accepted.global_position < baseline.baseline_global_position()
            || accepted.captured_high_water < baseline.captured_high_water()
        {
            return Err(ReplayBaselineV2AuthenticationError::Unauthorized);
        }
        match suffix {
            ReplayAcceptedSuffixProofV2::Empty
                if accepted.sequence == baseline.sequence()
                    && accepted.global_position == baseline.baseline_global_position()
                    && accepted.head_event_id == *baseline.head_event_id()
                    && accepted.head_integrity_digest == *baseline.head_integrity_digest()
                    && accepted.digest
                        == *accepted_projection_digest(baseline.promotion_view()) => {}
            ReplayAcceptedSuffixProofV2::LastEvent {
                event_id,
                integrity_digest,
                sequence,
                global_position,
                cursor,
            } if !cursor.is_empty()
                && cursor.len() <= 4096
                && accepted.sequence == sequence
                && accepted.global_position == global_position
                && accepted.head_event_id == event_id
                && accepted.head_integrity_digest == integrity_digest => {}
            _ => return Err(ReplayBaselineV2AuthenticationError::Unauthorized),
        }
        Ok(AuthenticatedAcceptedReplayProjectionV2 {
            projection: accepted.projection.view().clone(),
            digest: accepted.digest,
            sequence: accepted.sequence,
            global_position: accepted.global_position,
            head_event_id: accepted.head_event_id,
            head_integrity_digest: accepted.head_integrity_digest,
            captured_high_water: accepted.captured_high_water,
            baseline_evidence_digest: baseline.local_evidence_digest(),
        })
    }
}

impl AuthenticatedAcceptedReplayProjectionV2 {
    /// Returns the semantic projection accepted by the same resume admission.
    pub const fn promotion_view(&self) -> &promotion_projection::ReplayPromotionProjectionViewV1 {
        &self.projection
    }
    /// Returns the accepted projection digest.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    /// Returns the accepted aggregate sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Returns the accepted global log position.
    pub const fn global_position(&self) -> i64 {
        self.global_position
    }
    /// Returns the accepted current head identity.
    pub const fn head_event_id(&self) -> &[u8; 16] {
        &self.head_event_id
    }
    /// Returns the accepted current head integrity digest.
    pub const fn head_integrity_digest(&self) -> &[u8; 32] {
        &self.head_integrity_digest
    }
    /// Returns the high water captured with the accepted projection.
    pub const fn captured_high_water(&self) -> i64 {
        self.captured_high_water
    }
    /// Proves that this accepted projection belongs to the exact baseline.
    pub fn matches_baseline(&self, baseline: &AuthenticatedReplayBaselineV2) -> bool {
        bool::from(self.baseline_evidence_digest.ct_eq(&baseline.local_evidence_digest()))
    }
    /// Proves the persisted local baseline evidence belongs to this result.
    pub fn matches_local_evidence_digest(&self, evidence: &[u8; 32]) -> bool {
        bool::from(self.baseline_evidence_digest.ct_eq(evidence))
    }
    /// Derives a canonical local adapter payload from the accepted semantic view.
    pub fn local_projection(
        &self,
    ) -> Result<AuthenticatedLocalReplayProjectionV1, ReplayContractError> {
        let encoded = promotion_projection::canonical_local_promotion_json(&self.projection)?;
        Ok(AuthenticatedLocalReplayProjectionV1 {
            encoded: serde_json::to_vec(&encoded).expect("fixed local projection is serializable"),
        })
    }
}

impl AuthenticatedReplayBaselineCheckpointV2 {
    /// Proves that this admitted checkpoint belongs to the exact baseline.
    pub fn matches_baseline(&self, baseline: &AuthenticatedReplayBaselineV2) -> bool {
        bool::from(self.baseline_evidence_digest.ct_eq(&baseline.local_evidence_digest()))
    }
    /// Runs a native local-persistence operation over the admitted cursor.
    ///
    /// This narrow callback is an explicit native-Rust TCB seam; it is neither
    /// a transport getter nor a renderer/runne-runtime-client re-export surface.
    pub fn with_local_persistence_cursor<R>(&self, operation: impl FnOnce(&str) -> R) -> R {
        operation(&self.cursor)
    }
}

impl core::fmt::Debug for AuthenticatedReplayBaselineCheckpointV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthenticatedReplayBaselineCheckpointV2")
            .field("redacted", &true)
            .finish()
    }
}

impl core::fmt::Debug for AuthenticatedAcceptedReplayProjectionV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthenticatedAcceptedReplayProjectionV2")
            .field("sequence", &self.sequence)
            .field("redacted", &true)
            .finish()
    }
}

fn accepted_projection_digest(
    view: &promotion_projection::ReplayPromotionProjectionViewV1,
) -> &[u8; 32] {
    match view {
        promotion_projection::ReplayPromotionProjectionViewV1::Conversation(value) => {
            value.projection_digest()
        }
        promotion_projection::ReplayPromotionProjectionViewV1::TaskRun(value) => {
            value.promotion_digest()
        }
    }
}
