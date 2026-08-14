#[cfg(any(test, feature = "fixture-only"))]
use crate::{AuthorityError, CandidateBinding, Digest, SigningAuthorizedReceipt};
#[cfg(any(test, feature = "fixture-only"))]
use gocode_promotion_contracts::CanonicalPayloadKind as StageKind;
#[cfg(any(test, feature = "fixture-only"))]
use std::collections::BTreeMap;
#[cfg(any(test, feature = "fixture-only"))]
use std::io::Read as _;
#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PromotionId(pub(crate) String);
#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CommandId(String);
#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandFingerprint(Digest);
#[cfg(any(test, feature = "fixture-only"))]
#[cfg(any(test, feature = "fixture-only"))]
impl PromotionId {
    /// Construct a fixture promotion identifier only when it is safe for canonical JSON scope.
    ///
    /// # Errors
    /// Returns an error for an empty, oversized, or non-canonical identifier.
    pub fn try_fixture(value: &str) -> Result<Self, AuthorityError> {
        gocode_promotion_contracts::canonical_id(value)
            .then(|| Self(value.into()))
            .ok_or(AuthorityError::NonCanonicalPayload)
    }
    #[must_use]
    /// Construct a known-valid fixture identifier.
    ///
    /// # Panics
    /// Panics when `value` is not a canonical promotion identifier.
    pub fn fixture(value: &str) -> Self {
        Self::try_fixture(value).expect("fixture promotion id is canonical")
    }
}
#[cfg(any(test, feature = "fixture-only"))]
impl CommandId {
    #[must_use]
    pub fn fixture(value: &str) -> Self {
        Self(value.into())
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn is_canonical(&self) -> bool {
        gocode_promotion_contracts::canonical_id(&self.0)
    }
    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}
#[cfg(any(test, feature = "fixture-only"))]
impl CommandFingerprint {
    pub(crate) const fn derived(value: Digest) -> Self {
        Self(value)
    }
    pub(crate) const fn digest(self) -> Digest {
        self.0
    }
}
#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromotionState {
    Rc0Ingested,
    Rc1Review,
    QualifiedUnsigned,
    SigningAuthorized,
    SignedEnvelopesVerified,
    Rc3Review,
    PublicationAuthorized,
}
#[cfg(any(test, feature = "fixture-only"))]
#[derive(Debug, Eq, PartialEq)]
pub enum Mutation {
    Ingest {
        binding: CandidateBinding,
        admission: Box<crate::FixtureAdmission>,
    },
    StartRc1Review {},
    QualifyUnsigned {
        transition: Box<crate::VerifiedStageTransition>,
    },
    FixtureAuthorizeSigning {
        transition: Box<crate::VerifiedStageTransition>,
    },
    VerifySigned {
        proof: Box<crate::DurableThresholdProof>,
    },
    StartRc3Review {},
    FixtureAuthorizePublication {
        bundle: Box<crate::FixturePublicationBundle>,
    },
}
#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionOutcome {
    pub state: PromotionState,
    pub revision: u64,
    pub(crate) fixture: bool,
}
#[cfg(any(test, feature = "fixture-only"))]
impl TransactionOutcome {
    #[must_use]
    pub const fn is_fixture(&self) -> bool {
        self.fixture
    }
}
#[cfg(any(test, feature = "fixture-only"))]
pub trait PromotionStore {
    /// # Errors
    ///
    /// Fails closed for missing authority, stale revisions, replay divergence, or invalid state.
    fn transact(
        &mut self,
        id: &PromotionId,
        expected_revision: u64,
        command: CommandId,
        mutation: Mutation,
    ) -> Result<TransactionOutcome, AuthorityError>;
    /// Persist a no-capability reservation before contacting threshold authority.
    ///
    /// # Errors
    /// Returns an error for stale, divergent, competing, or non-authorized reservations.
    fn reserve_verify_signed(
        &mut self,
        id: &PromotionId,
        expected_revision: u64,
        command: CommandId,
        bundle: &crate::FixturePrevalidatedSignedBundle,
    ) -> Result<SigningAuthorizedReceipt, AuthorityError>;
}

/// Fixture store boundary for raw owner envelopes. Verification, nonce admission, and mutation
/// are co-located under the store transaction; no preverified stage handle can authorize commit.
#[cfg(any(test, feature = "fixture-only"))]
pub trait StageTransitionStore {
    /// Verify and commit one exact raw owner stage envelope under one store transaction.
    ///
    /// # Errors
    /// Returns an error when revalidation, reservation matching, state CAS, or persistence fails.
    fn verify_and_commit_stage_transition(
        &mut self,
        request: RawStageTransitionRequest<'_>,
    ) -> Result<TransactionOutcome, AuthorityError>;
}

/// Exact raw owner-envelope inputs accepted only by the co-located fixture transaction.
#[cfg(any(test, feature = "fixture-only"))]
pub struct RawStageTransitionRequest<'a> {
    pub promotion: &'a PromotionId,
    pub expected_revision: u64,
    pub command: CommandId,
    pub kind: StageKind,
    pub bytes: &'a [u8],
    pub expected_sha256: [u8; 32],
    pub bootstrap: &'a gocode_project_owner_authority::VerifiedPromotionBootstrap,
    pub publication_manifest: Option<&'a crate::InspectedCanonicalPayload>,
}

/// Authenticated fixture trust snapshot used to exercise expiry and revocation races.
#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone)]
pub struct StageTrustFixture {
    pub now: u64,
    pub utc: String,
    pub root_epoch: u64,
    pub role_floor: u64,
}
pub struct UnprovisionedPromotionStore;
/// Production authority status without opening any backend or effect capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionAuthorityStatus {
    NotProvisioned,
}
impl ProductionAuthorityStatus {
    #[must_use]
    pub const fn as_code(self) -> &'static str {
        "BLOCKED(PROMOTION_AUTHORITY_NOT_PROVISIONED)"
    }
}
#[cfg(any(test, feature = "fixture-only"))]
impl PromotionStore for UnprovisionedPromotionStore {
    fn transact(
        &mut self,
        _: &PromotionId,
        _: u64,
        _: CommandId,
        _: Mutation,
    ) -> Result<TransactionOutcome, AuthorityError> {
        Err(AuthorityError::AuthorityNotProvisioned)
    }
    fn reserve_verify_signed(
        &mut self,
        _: &PromotionId,
        _: u64,
        _: CommandId,
        _: &crate::FixturePrevalidatedSignedBundle,
    ) -> Result<SigningAuthorizedReceipt, AuthorityError> {
        Err(AuthorityError::AuthorityNotProvisioned)
    }
}
#[cfg(any(test, feature = "fixture-only"))]
impl StageTransitionStore for UnprovisionedPromotionStore {
    fn verify_and_commit_stage_transition(
        &mut self,
        _: RawStageTransitionRequest<'_>,
    ) -> Result<TransactionOutcome, AuthorityError> {
        Err(AuthorityError::AuthorityNotProvisioned)
    }
}
#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone)]
pub struct InMemoryPromotionStore {
    pub(crate) authority_instance: Digest,
    pub(crate) entries: BTreeMap<PromotionId, crate::store_machine::Record>,
    pub(crate) stage_claims: BTreeMap<String, crate::store_stage_claim::StoredStageClaim>,
    pub(crate) rc2_effect_ledger: crate::FixtureRc2EffectLeaseLedger,
    pub(crate) publication_effect_ledger: crate::FixturePublicationEffectLedger,
}
#[cfg(any(test, feature = "fixture-only"))]
impl Default for InMemoryPromotionStore {
    fn default() -> Self {
        Self::with_authority_instance(random_authority_instance())
    }
}
#[cfg(any(test, feature = "fixture-only"))]
impl InMemoryPromotionStore {
    pub(crate) fn with_authority_instance(authority_instance: Digest) -> Self {
        Self {
            authority_instance,
            entries: BTreeMap::new(),
            stage_claims: BTreeMap::new(),
            rc2_effect_ledger: crate::FixtureRc2EffectLeaseLedger::default(),
            publication_effect_ledger: crate::FixturePublicationEffectLedger::default(),
        }
    }
    /// Construct a deterministic fixture store identity for an explicitly controlled test.
    #[must_use]
    pub fn fixture_with_authority_instance(authority_instance: Digest) -> Self {
        Self::with_authority_instance(authority_instance)
    }
}
#[cfg(any(test, feature = "fixture-only"))]
fn random_authority_instance() -> Digest {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .expect("fixture authority instance randomness is available");
    Digest::from_bytes(bytes)
}
