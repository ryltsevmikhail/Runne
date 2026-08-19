/// Opaque, already authenticated replay-baseline evidence.
///
/// Runtime-client/AppCore must gain the production constructor; runne-local-store
/// deliberately does not accept caller-assembled authority claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayBaselineSeed {
    pub(crate) session_binding: String,
    pub(crate) promotion_codec: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) scope_digest: String,
    pub(crate) authenticated_scope_digest: String,
    pub(crate) schema_version: u16,
    pub(crate) head_event_id: String,
    pub(crate) head_integrity_digest: String,
    pub(crate) retention_manifest_digest: String,
    pub(crate) witness_digest: String,
    pub(crate) retention_floor: u64,
    pub(crate) retention_high_water: u64,
    pub(crate) retention_generation: u64,
    pub(crate) issued_at: u64,
    pub(crate) baseline_sequence: u64,
    pub(crate) baseline_version: u64,
    pub(crate) baseline_position: u64,
    pub(crate) expires_at: u64,
}

#[cfg(feature = "test-support")]
impl ReplayBaselineSeed {
    /// # Errors
    ///
    /// Returns an error when test evidence exceeds the production bounds.
    pub fn for_local_store_test(
        scope: &ReplayScopeKey,
        session_binding: impl Into<String>,
        promotion_codec: impl Into<String>,
        payload: &[u8],
        baseline_sequence: u64,
        baseline_position: u64,
        expires_at: u64,
    ) -> Result<Self, ReplayStoreError> {
        let session_binding = session_binding.into();
        let promotion_codec = promotion_codec.into();
        if session_binding.is_empty()
            || session_binding.len() > 256
            || promotion_codec.is_empty()
            || promotion_codec.len() > 64
            || payload.is_empty()
            || payload.len() > 1_048_576
            || baseline_sequence == 0
            || expires_at == 0
        {
            return Err(ReplayStoreError::InvalidBaseline);
        }
        Ok(Self {
            session_binding: digest(session_binding.as_bytes()),
            promotion_codec,
            payload: payload.to_vec(),
            scope_digest: scope_digest(scope),
            authenticated_scope_digest: digest(b"authenticated-scope"),
            schema_version: 2,
            head_event_id: "00000000-0000-7000-8000-000000000001".to_owned(),
            head_integrity_digest: digest(payload),
            retention_manifest_digest: digest(b"test-retention-manifest"),
            witness_digest: digest(b"test-v2-witness"),
            retention_floor: baseline_position,
            retention_high_water: baseline_position,
            retention_generation: baseline_position,
            issued_at: 1,
            baseline_sequence,
            baseline_version: baseline_sequence,
            baseline_position,
            expires_at,
        })
    }
}

pub(crate) fn scope_digest(scope: &ReplayScopeKey) -> String {
    let mut bytes = Vec::new();
    for value in [
        scope.runtime_authority.as_bytes(),
        scope.principal.as_bytes(),
        scope.lineage.as_bytes(),
        scope.scope.as_bytes(),
        scope.binding_digest.as_bytes(),
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    digest(&bytes)
}

pub(crate) fn valid_baseline_seed(
    scope: &ReplayScopeKey,
    seed: &ReplayBaselineSeed,
    now: u64,
) -> bool {
    let positive = [
        seed.baseline_sequence,
        seed.baseline_version,
        seed.baseline_position,
        seed.retention_floor,
        seed.retention_high_water,
        seed.retention_generation,
        seed.issued_at,
        seed.expires_at,
    ];
    positive
        .into_iter()
        .all(|value| value > 0 && i64::try_from(value).is_ok())
        && seed.issued_at <= now
        && now < seed.expires_at
        && seed.schema_version == 2
        && seed.scope_digest == scope_digest(scope)
        && !seed.head_event_id.is_empty()
        && seed.baseline_version == seed.baseline_sequence
        && seed.baseline_position >= seed.retention_floor
        && seed.baseline_position <= seed.retention_high_water
        && !seed.payload.is_empty()
        && seed.payload.len() <= 1_048_576
        && seed.session_binding.len() == 64
        && !seed.promotion_codec.is_empty()
        && seed.promotion_codec.len() <= 64
        && valid_digest(&seed.head_integrity_digest)
        && valid_digest(&seed.retention_manifest_digest)
        && valid_digest(&seed.session_binding)
        && valid_digest(&seed.authenticated_scope_digest)
        && valid_digest(&seed.witness_digest)
        && uuid_v7(&seed.head_event_id)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn uuid_v7(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| value.as_bytes()[index] == b'-')
        && value.as_bytes()[14] == b'7'
        && matches!(value.as_bytes()[19], b'8'..=b'9' | b'a'..=b'b')
        && value.bytes().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(&byte)
        })
}

pub(crate) fn baseline_evidence_digest(seed: &ReplayBaselineSeed) -> String {
    let mut bytes = Vec::new();
    for value in [
        seed.session_binding.as_bytes(),
        seed.promotion_codec.as_bytes(),
        &seed.payload,
        seed.scope_digest.as_bytes(),
        seed.authenticated_scope_digest.as_bytes(),
        seed.head_event_id.as_bytes(),
        seed.head_integrity_digest.as_bytes(),
        seed.retention_manifest_digest.as_bytes(),
        seed.witness_digest.as_bytes(),
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    for value in [
        u64::from(seed.schema_version),
        seed.baseline_sequence,
        seed.baseline_version,
        seed.baseline_position,
        seed.retention_floor,
        seed.retention_high_water,
        seed.retention_generation,
        seed.issued_at,
        seed.expires_at,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    digest(&bytes)
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(value))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowReplayId(pub(crate) String);

impl ShadowReplayId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowResumeAcceptance {
    pub(crate) evidence_digest: String,
    pub(crate) cursor: String,
    pub(crate) generation: u64,
    pub(crate) event_sequence: u64,
    pub(crate) projection_revision: u64,
    pub(crate) projection_payload: Vec<u8>,
    pub(crate) projection_digest: String,
}

/// Local-only promotion coordinates chosen by the `AppCore` operation fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowPromotionCoordinates {
    pub generation: u64,
    pub projection_revision: u64,
}

#[cfg(feature = "test-support")]
impl ShadowResumeAcceptance {
    /// # Errors
    ///
    /// Returns an error when the supplied test acceptance exceeds persisted bounds.
    pub fn for_local_store_test(
        seed: &ReplayBaselineSeed,
        cursor: impl Into<String>,
        generation: u64,
        projection_revision: u64,
        projection_payload: &[u8],
    ) -> Result<Self, ReplayStoreError> {
        let cursor = cursor.into();
        let projection_digest = digest(projection_payload);
        if cursor.is_empty()
            || cursor.len() > 4096
            || projection_payload.is_empty()
            || projection_payload.len() > 1_048_576
            || projection_revision > i64::MAX as u64
        {
            return Err(ReplayStoreError::InvalidBaseline);
        }
        Ok(Self {
            evidence_digest: baseline_evidence_digest(seed),
            cursor,
            generation,
            event_sequence: seed.baseline_sequence,
            projection_revision,
            projection_payload: projection_payload.to_vec(),
            projection_digest,
        })
    }
}
