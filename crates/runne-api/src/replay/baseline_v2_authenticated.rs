use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;


type HmacSha256 = Hmac<sha2::Sha256>;

/// Verification failure for an unauthenticated V2 replay baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayBaselineV2AuthenticationError {
    /// The wire claims, binding, witness or requested scope did not match.
    Unauthorized,
    /// The native runtime authority material was structurally unusable.
    InvalidAuthority,
}

/// Native-runtime verifier for a session-bound V2 replay baseline.
///
/// Construction is deliberately limited to the native Rust TCB: possession of
/// the 32-byte runtime-session authority is already the authenticated runtime
/// trust boundary. The value exposes neither that authority nor its derived
/// witness key and never accepts caller-assembled authenticated fields.
pub struct ReplayBaselineV2Authenticator {
    authority: Zeroizing<[u8; 32]>,
    binding: RuntimeSessionBinding,
}

/// Opaque, authenticated V2 baseline capability.
///
/// It exposes only bound semantic promotion state and bounded continuity facts;
/// it has no serde implementation and no raw witness, wire, or snapshot API.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedReplayBaselineV2 {
    fields: UnauthenticatedReplayRetentionBaselineFieldsV2,
    promotion: promotion_projection::ReplayPromotionProjectionViewV1,
    verifier_tag: [u8; 32],
    durable_binding_digest: [u8; 32],
}

/// Opaque canonical local persistence projection derived from an authenticated
/// semantic view. It is deliberately distinct from the authoritative snapshot
/// codec and cannot be constructed from caller-provided bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedLocalReplayProjectionV1 {
    encoded: Vec<u8>,
}

impl ReplayBaselineV2Authenticator {
    /// Creates the verifier from already authenticated native-session material.
    ///
    /// # Errors
    ///
    /// Returns an error for an all-zero authority, which is never a valid
    /// runtime-session credential.
    pub fn from_native_rust_tcb(
        authority: [u8; 32],
        binding: RuntimeSessionBinding,
    ) -> Result<Self, ReplayBaselineV2AuthenticationError> {
        (authority != [0; 32])
            .then_some(Self {
                authority: Zeroizing::new(authority),
                binding,
            })
            .ok_or(ReplayBaselineV2AuthenticationError::InvalidAuthority)
    }

    /// Verifies one exact V2 wire against this session and requested aggregate.
    pub fn verify_wire_v2(
        &self,
        wire: &ReplayRetentionBaselineWireV2,
        expected_kind: ApiReplayAggregateKind,
        expected_id: [u8; 16],
        now_unix_ms: u64,
    ) -> Result<AuthenticatedReplayBaselineV2, ReplayBaselineV2AuthenticationError> {
        let fields = wire.to_unauthenticated_fields();
        let stable = self.binding.stable();
        if fields.authority_id != *stable.authority_id()
            || fields.principal_id != stable.principal_id().as_str()
            || fields.lineage_id != *stable.lineage_id().as_bytes()
            || fields.runtime_session_binding_digest != self.binding.canonical_digest()
            || fields.replay_scope_digest
                != super::canonical_aggregate_replay_scope_digest(expected_kind, &expected_id)
            || fields.issued_at_unix_ms > now_unix_ms
            || now_unix_ms >= fields.expires_at_unix_ms
        {
            return Err(ReplayBaselineV2AuthenticationError::Unauthorized);
        }
        let promotion = validate_unauthenticated_replay_retention_baseline_v2(
            wire,
            expected_kind,
            &expected_id,
        )
        .map_err(|_| ReplayBaselineV2AuthenticationError::Unauthorized)?;
        let expected = self.witness_mac(wire)?;
        if !bool::from(expected.ct_eq(&fields.witness_mac)) {
            return Err(ReplayBaselineV2AuthenticationError::Unauthorized);
        }
        Ok(AuthenticatedReplayBaselineV2 {
            fields,
            promotion: promotion.view().clone(),
            verifier_tag: self.verifier_tag(),
            durable_binding_digest: self.durable_binding_digest(),
        })
    }

    fn witness_mac(
        &self,
        wire: &ReplayRetentionBaselineWireV2,
    ) -> Result<[u8; 32], ReplayBaselineV2AuthenticationError> {
        let binding = self.binding.canonical_digest();
        let mut derive = HmacSha256::new_from_slice(self.authority.as_ref())
            .map_err(|_| ReplayBaselineV2AuthenticationError::InvalidAuthority)?;
        derive.update(super::REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V2);
        derive.update(&binding);
        let key: [u8; 32] = derive.finalize().into_bytes().into();
        let mut mac = HmacSha256::new_from_slice(&key)
            .map_err(|_| ReplayBaselineV2AuthenticationError::InvalidAuthority)?;
        mac.update(
            &super::replay_retention_baseline_v2_transcript(wire)
                .map_err(|_: ReplayRetentionBaselineWireError| {
                    ReplayBaselineV2AuthenticationError::Unauthorized
                })?,
        );
        Ok(mac.finalize().into_bytes().into())
    }

    fn verifier_tag(&self) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(self.authority.as_ref())
            .expect("fixed native runtime authority");
        mac.update(b"runne.replay-retention-baseline.v2.verifier-tag\0");
        mac.update(&self.binding.canonical_digest());
        mac.finalize().into_bytes().into()
    }

    fn durable_binding_digest(&self) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        let stable = self.binding.stable();
        let fields = [
            lower_hex(stable.authority_id()), stable.principal_id().as_str().to_owned(),
            uuid_text(stable.lineage_id().as_bytes()), stable.profile_id().to_owned(),
            lower_hex(stable.schema_hash()), lower_hex(stable.capability_digest()),
        ];
        let mut digest = Sha256::new();
        digest.update(b"runne/replay-persistence-binding/v1\0");
        for value in fields {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest.finalize().into()
    }
}

impl AuthenticatedReplayBaselineV2 {
    /// Returns the closed, read-only promotion view bound by the witness.
    pub const fn promotion_view(&self) -> &promotion_projection::ReplayPromotionProjectionViewV1 {
        &self.promotion
    }
    /// Returns the authenticated aggregate kind.
    pub const fn aggregate_kind(&self) -> ApiReplayAggregateKind { self.fields.aggregate_kind }
    /// Returns the authenticated aggregate identity.
    pub const fn aggregate_id(&self) -> &[u8; 16] { &self.fields.aggregate_id }
    /// Returns the authenticated stable runtime authority.
    pub const fn authority_id(&self) -> &[u8; 16] { &self.fields.authority_id }
    /// Returns the authenticated stable principal.
    pub fn principal_id(&self) -> &str { &self.fields.principal_id }
    /// Returns the authenticated event-log lineage.
    pub const fn lineage_id(&self) -> &[u8; 16] { &self.fields.lineage_id }
    /// Returns the aggregate-local accepted sequence.
    pub const fn sequence(&self) -> u64 { self.fields.sequence }
    /// Returns the session-binding digest needed to bind protected local state.
    pub const fn runtime_session_binding_digest(&self) -> &[u8; 32] {
        &self.fields.runtime_session_binding_digest
    }
    /// Returns the authenticated aggregate scope digest.
    pub const fn replay_scope_digest(&self) -> &[u8; 32] { &self.fields.replay_scope_digest }
    /// Returns the captured global baseline position.
    pub const fn baseline_global_position(&self) -> i64 { self.fields.baseline_global_position }
    /// Returns the retention generation.
    pub const fn retention_generation(&self) -> u64 { self.fields.retention_generation }
    /// Returns the authenticated retention floor.
    pub const fn retained_floor(&self) -> i64 { self.fields.retained_floor }
    /// Returns the high water captured with the baseline.
    pub const fn captured_high_water(&self) -> i64 { self.fields.captured_high_water }
    /// Returns the promotion codec selected by the authenticated server.
    pub const fn promotion_codec(&self) -> u8 { self.fields.promotion_codec }
    /// Returns the authenticated historical head identity.
    pub const fn head_event_id(&self) -> &[u8; 16] { &self.fields.head_event_id }
    /// Returns the authenticated historical head integrity digest.
    pub const fn head_integrity_digest(&self) -> &[u8; 32] { &self.fields.head_integrity_digest }
    /// Returns the authenticated retention-manifest digest.
    pub const fn retention_manifest_digest(&self) -> &[u8; 32] {
        &self.fields.retention_manifest_digest
    }
    /// Returns the authenticated issue time.
    pub const fn issued_at_unix_ms(&self) -> u64 { self.fields.issued_at_unix_ms }
    /// Returns the authenticated expiry time.
    pub const fn expires_at_unix_ms(&self) -> u64 { self.fields.expires_at_unix_ms }
    /// Returns a non-secret digest binding all local-store-relevant evidence.
    pub fn local_evidence_digest(&self) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"runne.replay.authenticated-baseline.v2.local-evidence\0");
        digest.update(self.fields.runtime_session_binding_digest);
        digest.update(self.fields.replay_scope_digest);
        digest.update(self.fields.head_event_id);
        digest.update(self.fields.head_integrity_digest);
        digest.update(self.fields.retention_manifest_digest);
        digest.update(self.fields.witness_mac);
        digest.finalize().into()
    }

    /// Returns the stable persistence binding used by the native local store.
    pub fn durable_replay_binding_digest(&self) -> [u8; 32] {
        self.durable_binding_digest
    }

    /// Derives the only local persistence payload accepted by the V8 adapter.
    pub fn local_projection(
        &self,
    ) -> Result<AuthenticatedLocalReplayProjectionV1, ReplayContractError> {
        let encoded = promotion_projection::canonical_local_promotion_json(&self.promotion)?;
        Ok(AuthenticatedLocalReplayProjectionV1 {
            encoded: serde_json::to_vec(&encoded).expect("fixed local projection is serializable"),
        })
    }
}

fn lower_hex(value: &[u8]) -> String {
    use core::fmt::Write as _;
    value.iter().fold(String::with_capacity(value.len() * 2), |mut out, byte| {
        write!(&mut out, "{byte:02x}").expect("writing to String is infallible");
        out
    })
}

fn uuid_text(value: &[u8; 16]) -> String {
    let value = lower_hex(value);
    format!("{}-{}-{}-{}-{}", &value[..8], &value[8..12], &value[12..16], &value[16..20], &value[20..])
}

impl AuthenticatedLocalReplayProjectionV1 {
    /// Returns canonical local adapter bytes, never an authoritative snapshot.
    pub fn local_persistence_bytes(&self) -> &[u8] { &self.encoded }
}

impl core::fmt::Debug for AuthenticatedReplayBaselineV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthenticatedReplayBaselineV2")
            .field("aggregate_kind", &self.fields.aggregate_kind)
            .field("redacted", &true)
            .finish()
    }
}

impl core::fmt::Debug for AuthenticatedLocalReplayProjectionV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthenticatedLocalReplayProjectionV1")
            .field("redacted", &true)
            .finish()
    }
}
