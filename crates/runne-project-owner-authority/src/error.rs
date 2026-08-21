use thiserror::Error;

/// Fail-closed errors for project-owner authority data.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorityError {
    /// JSON object contains the same key more than once.
    #[error("duplicate JSON key")]
    DuplicateKey(String),
    /// JSON object contains a field outside its closed contract.
    #[error("unknown JSON field")]
    UnknownField(String),
    /// Receipt document paths must be unique by their exact UTF-8 bytes.
    #[error("duplicate receipt document path")]
    DuplicateDocumentPath(String),
    /// Input bytes are not valid UTF-8.
    #[error("input is not valid UTF-8")]
    InvalidUtf8,
    /// Input is not valid JSON for this protocol.
    #[error("input is not valid JSON")]
    InvalidJson,
    /// Parsed JSON cannot populate the receipt model.
    #[error("input does not match the receipt model")]
    InvalidReceipt,
    /// Canonical JSON serialization unexpectedly failed.
    #[error("canonical receipt serialization failed")]
    Serialization,
    /// A length-prefixed protocol field exceeds its representable size.
    #[error("protocol field exceeds its maximum encoded length")]
    LengthTooLarge,
    /// Genesis proof-of-possession does not verify for its public key.
    #[error("invalid genesis proof of possession")]
    InvalidProofOfPossession,
    /// The public-key identifier is not derived from the supplied public key.
    #[error("invalid project-owner key identifier")]
    InvalidKeyId,
    /// Trust-config schema digest identifiers are not strictly sorted and unique.
    #[error("invalid trust-config schema digests")]
    InvalidSchemaDigests,
    /// V3 promotion-schema pins have not been finalized from checked-in bytes.
    #[error("TRUST_V3_PINS_NOT_FINALIZED")]
    TrustV3PinsNotFinalized,
    /// Retained public V4 pin-finalization error for compatibility; finalized pins are active.
    #[error("TRUST_V4_PINS_NOT_FINALIZED")]
    TrustV4PinsNotFinalized,
    /// A legacy or mixed authority version attempted active promotion admission.
    #[error("AUTHORITY_VERSION_SUPERSEDED")]
    AuthorityVersionSuperseded,
    /// Genesis fields do not match the fixed protocol constants.
    #[error("invalid genesis configuration")]
    InvalidGenesis,
    /// No independently confirmed local anchor is available.
    #[error("BOOTSTRAP_CONFIRMATION_REQUIRED")]
    BootstrapConfirmationRequired,
    /// A candidate trust configuration is below the local epoch floor.
    #[error("trust epoch rollback")]
    TrustEpochRollback,
    /// A candidate conflicts with the locally pinned trust configuration.
    #[error("trust configuration fork")]
    TrustConfigFork,
    /// A trust configuration does not belong to the anchored repository.
    #[error("trust repository mismatch")]
    RepositoryMismatch,
    /// A supplied anchor has no valid project-owner epoch floor.
    #[error("invalid trust anchor")]
    InvalidTrustAnchor,
    /// A purpose profile is not the closed protocol profile.
    #[error("invalid purpose profile")]
    InvalidPurposeProfile,
    /// A document binding is not a safe regular Git blob binding.
    #[error("invalid document binding")]
    InvalidDocumentBinding,
    /// Receipt fields do not bind the verified trust configuration.
    #[error("invalid receipt trust binding")]
    InvalidReceiptTrust,
    /// Receipt signature does not verify for the pinned project-owner key.
    #[error("invalid receipt signature")]
    InvalidReceiptSignature,
    /// Receipt SHA-256 does not match canonical checked-in LF bytes.
    #[error("invalid receipt digest")]
    InvalidReceiptDigest,
    /// Checked-in receipt bytes differ from their exact canonical representation.
    #[error("noncanonical checked-in receipt bytes")]
    InvalidCanonicalReceipt,
    /// Promotion bootstrap fields do not meet the closed authority contract.
    #[error("invalid promotion bootstrap")]
    InvalidPromotionBootstrap,
    /// The caller did not supply an authenticated durable promotion-bootstrap context.
    #[error("promotion bootstrap verification context is required")]
    PromotionBootstrapVerificationContextRequired,
    /// A new promotion bootstrap is outside its trusted validity or revocation boundary.
    #[error("promotion bootstrap is stale or revoked")]
    StaleOrRevokedPromotionBootstrap,
    /// A durable promotion-bootstrap admission conflicts with the expected lineage or generation.
    #[error("promotion bootstrap admission conflict")]
    PromotionBootstrapAdmissionConflict,
    /// A delegated stage credential violates isolation or closure requirements.
    #[error("invalid stage delegation")]
    InvalidDelegation,
    /// A release stage envelope fails its closed authority contract.
    #[error("invalid stage envelope")]
    InvalidStageEnvelope,
    /// A release evidence envelope fails its closed authority contract.
    #[error("invalid evidence envelope")]
    InvalidEvidenceEnvelope,
    /// A root-signed publication destination allowlist fails its closed contract.
    #[error("invalid destination allowlist")]
    InvalidDestinationAllowlist,
    /// The caller did not supply a trusted durable stage verification context.
    #[error("stage verification context is required")]
    StageVerificationContextRequired,
    /// A stage envelope is outside its trusted validity or revocation boundary.
    #[error("stage envelope is stale or revoked")]
    StaleOrRevokedStageEnvelope,
    /// A stage envelope nonce was previously claimed in durable storage.
    #[error("stage envelope authorization nonce was replayed")]
    ReplayedStageEnvelope,
    /// A rotation did not advance exactly one epoch from its predecessor.
    #[error("invalid rotation epoch")]
    InvalidRotationEpoch,
    /// A rotation does not bind the exact predecessor trust configuration.
    #[error("invalid rotation predecessor")]
    InvalidRotationPredecessor,
    /// A rotation does not bind the active old key and epoch.
    #[error("invalid rotation old key")]
    InvalidRotationOldKey,
    /// A rotation attempts to retain or otherwise reuse the active key.
    #[error("invalid rotation key")]
    InvalidRotationKey,
    /// The old-key authorization is missing or invalid.
    #[error("invalid rotation old authorization")]
    InvalidRotationOldAuthorization,
    /// The new-key proof of possession is missing or invalid.
    #[error("invalid rotation new proof of possession")]
    InvalidRotationNewPop,
    /// A key appears more than once in a rotation continuity chain.
    #[error("reused rotation key")]
    ReusedRotationKey,
    /// Backup KDF parameters violate the version-1 resource floor or ceiling.
    #[error("invalid backup parameters")]
    InvalidBackupParameters,
    /// Backup metadata is not a canonical version-1 public container.
    #[error("invalid backup metadata")]
    InvalidBackupMetadata,
    /// Backup metadata or plaintext does not match the supplied public trust binding.
    #[error("invalid backup binding")]
    InvalidBackupBinding,
    /// Caller did not provide cryptographically secure backup randomness.
    #[error("backup randomness unavailable")]
    BackupRandomnessUnavailable,
    /// Backup authentication failed without exposing whether a passphrase or bytes were wrong.
    #[error("BACKUP_TAMPERED_OR_WRONG_PASSPHRASE")]
    BackupTamperedOrWrongPassphrase,
}
