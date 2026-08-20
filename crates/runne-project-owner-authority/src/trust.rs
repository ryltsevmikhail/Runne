//! Public genesis verification and local trust-floor checks.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, framed_transcript,
    trust_canonical::{canonical_config, hex},
};

const CONFIG_SCHEMA: &str = "gocode.project-owner.trust-config/1";
const KEY_ID_DOMAIN: &[u8] = b"gocode.project-owner.key-id/1";
const POP_DOMAIN: &[u8] = b"gocode.project-owner.genesis-pop/1";
const ROTATION_POP_DOMAIN: &[u8] = b"gocode.project-owner.rotation-new-proof-of-possession/1";

/// One pinned schema digest in a project-owner trust configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaDigest {
    /// Versioned schema identifier.
    pub schema_id: String,
    /// SHA-256 of the exact schema bytes.
    pub schema_sha256: [u8; 32],
}

/// Public immutable genesis configuration for the sole project owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectOwnerTrustConfigV1 {
    /// Fixed trust-config schema identifier.
    pub schema_version: String,
    /// Repository whose authority this config governs.
    pub repository_id: String,
    /// Fixed project-owner role.
    pub role: String,
    /// Genesis epoch, always one.
    pub epoch: u64,
    /// Domain-separated identifier of `public_key`.
    pub key_id: [u8; 32],
    /// Ed25519 public-key bytes.
    pub public_key: [u8; 32],
    /// Exact schemas accepted by this trust configuration.
    pub schema_digests: Vec<SchemaDigest>,
    /// Signature proving possession of `public_key` at genesis.
    pub proof_of_possession: [u8; 64],
    /// Genesis cannot claim a predecessor.
    pub predecessor: Option<[u8; 32]>,
}

/// Explicitly supplied local trust state; this core never performs TOFU.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustAnchorState {
    /// No out-of-band confirmation has been supplied.
    Missing,
    /// A manually confirmed local repository and high-water mark.
    Confirmed {
        /// Pinned repository identifier.
        repository_id: String,
        /// Highest accepted key epoch.
        highest_key_epoch: u64,
        /// SHA-256 of the accepted canonical trust configuration.
        accepted_trust_config_sha256: [u8; 32],
    },
}

impl TrustAnchorState {
    /// Construct an unconfirmed state that must never authorize bootstrap.
    #[must_use]
    pub const fn missing() -> Self {
        Self::Missing
    }

    /// Construct an independently confirmed local trust anchor.
    #[must_use]
    pub const fn confirmed(
        repository_id: String,
        highest_key_epoch: u64,
        accepted: [u8; 32],
    ) -> Self {
        Self::Confirmed {
            repository_id,
            highest_key_epoch,
            accepted_trust_config_sha256: accepted,
        }
    }
}

/// Derive the fixed-domain SHA-256 identifier for a public key.
#[must_use]
pub fn key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(public_key);
    hasher.finalize().into()
}

/// Canonical full genesis bytes, sorted by UTF-8 keys and terminated by LF.
///
/// # Errors
/// Returns [`AuthorityError::InvalidSchemaDigests`] for a noncanonical schema list.
pub fn canonical_genesis(config: &ProjectOwnerTrustConfigV1) -> Result<Vec<u8>, AuthorityError> {
    canonical_config(config, true)
}

/// Canonical genesis bytes excluding the proof-of-possession signature.
///
/// # Errors
/// Returns [`AuthorityError::InvalidSchemaDigests`] for a noncanonical schema list.
pub fn canonical_genesis_without_pop(
    config: &ProjectOwnerTrustConfigV1,
) -> Result<Vec<u8>, AuthorityError> {
    canonical_config(config, false)
}

/// Build the exact domain-separated genesis proof-of-possession transcript.
///
/// # Errors
/// Returns an error when the configuration cannot be canonically serialized.
pub fn genesis_pop_transcript(
    config: &ProjectOwnerTrustConfigV1,
) -> Result<Vec<u8>, AuthorityError> {
    framed_transcript(POP_DOMAIN, &canonical_genesis_without_pop(config)?)
}

/// Hex SHA-256 fingerprint for typed, out-of-band genesis confirmation.
///
/// # Errors
///
/// Propagates an invalid canonical schema list.
pub fn bootstrap_fingerprint(config: &ProjectOwnerTrustConfigV1) -> Result<String, AuthorityError> {
    Ok(hex(&Sha256::digest(canonical_genesis(config)?)))
}

/// Verify fixed genesis fields, key binding, canonical schema list, and `PoP`.
///
/// # Errors
///
/// Returns a fail-closed error for any fixed-field, key, list, or signature mismatch.
pub fn verify_genesis(config: &ProjectOwnerTrustConfigV1) -> Result<(), AuthorityError> {
    if !has_valid_fixed_fields(config) || config.epoch != 1 || config.predecessor.is_some() {
        return Err(AuthorityError::InvalidGenesis);
    }
    if config.key_id != key_id(&config.public_key) {
        return Err(AuthorityError::InvalidKeyId);
    }
    canonical_genesis_without_pop(config)?;
    let key = VerifyingKey::from_bytes(&config.public_key)
        .map_err(|_| AuthorityError::InvalidProofOfPossession)?;
    let signature = Signature::from_bytes(&config.proof_of_possession);
    let message = genesis_pop_transcript(config)?;
    key.verify_strict(&message, &signature)
        .map_err(|_| AuthorityError::InvalidProofOfPossession)
}

/// Verify the self-proof and structural shape of any active trust configuration.
///
/// This proves key possession only. Callers must separately establish the full
/// predecessor chain and local anchor before treating the configuration as trusted.
///
/// # Errors
///
/// Returns a fail-closed error for invalid fixed fields, epoch/predecessor shape,
/// key binding, schema digests, or strict Ed25519 proof verification.
pub fn verify_active_trust_config(
    config: &ProjectOwnerTrustConfigV1,
) -> Result<(), AuthorityError> {
    if config.epoch == 1 {
        return verify_genesis(config);
    }
    if config.epoch < 2 || !has_valid_fixed_fields(config) || config.predecessor.is_none() {
        return Err(AuthorityError::InvalidGenesis);
    }
    if config.key_id != key_id(&config.public_key) {
        return Err(AuthorityError::InvalidKeyId);
    }
    let payload = canonical_genesis_without_pop(config)?;
    let message = framed_transcript(ROTATION_POP_DOMAIN, &payload)?;
    let key = VerifyingKey::from_bytes(&config.public_key)
        .map_err(|_| AuthorityError::InvalidProofOfPossession)?;
    key.verify_strict(
        &message,
        &Signature::from_bytes(&config.proof_of_possession),
    )
    .map_err(|_| AuthorityError::InvalidProofOfPossession)
}

pub fn has_valid_fixed_fields(config: &ProjectOwnerTrustConfigV1) -> bool {
    config.schema_version == CONFIG_SCHEMA
        && config.repository_id == "gocode"
        && config.role == "PROJECT_OWNER"
}

pub fn verify_chain_anchor(
    config: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
) -> Result<(), AuthorityError> {
    let TrustAnchorState::Confirmed {
        repository_id,
        highest_key_epoch,
        accepted_trust_config_sha256,
    } = anchor
    else {
        return Err(AuthorityError::BootstrapConfirmationRequired);
    };
    if *highest_key_epoch == 0 {
        return Err(AuthorityError::InvalidTrustAnchor);
    }
    if config.repository_id != *repository_id {
        return Err(AuthorityError::RepositoryMismatch);
    }
    if config.epoch < *highest_key_epoch {
        return Err(AuthorityError::TrustEpochRollback);
    }
    if config.epoch == *highest_key_epoch && config.sha256()? != *accepted_trust_config_sha256 {
        return Err(AuthorityError::TrustConfigFork);
    }
    Ok(())
}

pub fn verify_pinned_chain_member(
    config: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
) -> Result<(), AuthorityError> {
    let TrustAnchorState::Confirmed {
        repository_id,
        highest_key_epoch,
        accepted_trust_config_sha256,
    } = anchor
    else {
        return Err(AuthorityError::BootstrapConfirmationRequired);
    };
    if *highest_key_epoch == 0 {
        return Err(AuthorityError::InvalidTrustAnchor);
    }
    if config.repository_id != *repository_id {
        return Err(AuthorityError::RepositoryMismatch);
    }
    if config.epoch == *highest_key_epoch && config.sha256()? != *accepted_trust_config_sha256 {
        return Err(AuthorityError::TrustConfigFork);
    }
    Ok(())
}

/// Check the exact accepted configuration SHA against a supplied local anchor.
///
/// # Errors
///
/// Returns [`AuthorityError::BootstrapConfirmationRequired`] or a fork error.
pub fn verify_anchor(
    candidate_sha256: [u8; 32],
    anchor: &TrustAnchorState,
) -> Result<(), AuthorityError> {
    match anchor {
        TrustAnchorState::Missing => Err(AuthorityError::BootstrapConfirmationRequired),
        TrustAnchorState::Confirmed {
            accepted_trust_config_sha256,
            ..
        } if *accepted_trust_config_sha256 == candidate_sha256 => Ok(()),
        TrustAnchorState::Confirmed { .. } => Err(AuthorityError::TrustConfigFork),
    }
}

/// Verify a genesis candidate against an explicit local anchor without TOFU.
///
/// # Errors
///
/// Returns a fail-closed error for missing anchors, rollback, repository, or genesis failure.
pub fn verify_trust_config(
    config: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
) -> Result<(), AuthorityError> {
    let TrustAnchorState::Confirmed {
        repository_id,
        highest_key_epoch,
        ..
    } = anchor
    else {
        return Err(AuthorityError::BootstrapConfirmationRequired);
    };
    if config.repository_id != *repository_id {
        return Err(AuthorityError::RepositoryMismatch);
    }
    if config.epoch < *highest_key_epoch {
        return Err(AuthorityError::TrustEpochRollback);
    }
    if *highest_key_epoch == 0 {
        return Err(AuthorityError::InvalidTrustAnchor);
    }
    verify_active_trust_config(config)?;
    verify_anchor(config.sha256()?, anchor)
}

impl ProjectOwnerTrustConfigV1 {
    /// SHA-256 of canonical full genesis bytes.
    ///
    /// # Errors
    ///
    /// Propagates an invalid canonical schema list.
    pub fn sha256(&self) -> Result<[u8; 32], AuthorityError> {
        Ok(Sha256::digest(canonical_genesis(self)?).into())
    }
}
