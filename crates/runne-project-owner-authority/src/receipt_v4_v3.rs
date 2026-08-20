//! Production V4 promotion-bootstrap signing and verification through V3 trust.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, PromotionBootstrapV4, SignedPromotionBootstrapV4, Signer, SigningDomain,
    VerifiedDocumentReconciliation, VerifiedTrustConfigV3,
    canonical_checked_in_promotion_bootstrap, canonical_unsigned_promotion_bootstrap, key_id,
    promotion_schema_pins, receipt_validation, signing_transcript,
};

/// Sign a promotion bootstrap with verified V3 root trust.
///
/// # Errors
/// Returns a fail-closed error for unfinished pins, trust, predecessor, fields, or signature.
pub fn sign_promotion_bootstrap_v3(
    trust: &VerifiedTrustConfigV3,
    predecessor: &VerifiedDocumentReconciliation,
    mut unsigned: PromotionBootstrapV4,
    signer: &dyn Signer,
) -> Result<SignedPromotionBootstrapV4, AuthorityError> {
    let trust = trust.config();
    if trust.schema_digests != promotion_schema_pins()? {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    predecessor.authorizes_v3(trust)?;
    unsigned.predecessor_receipt_sha256 = predecessor.receipt_sha256();
    unsigned.trust_config_sha256 = receipt_validation::hex(&trust.sha256()?);
    unsigned.key_id = receipt_validation::hex(&key_id(&trust.public_key));
    unsigned.key_epoch = trust.epoch;
    crate::receipt_v4_validation::validate_bootstrap(&unsigned, trust.public_key)?;
    let canonical = canonical_unsigned_promotion_bootstrap(&unsigned)?;
    let domain = SigningDomain::new(crate::RECEIPT_SCHEMA_V4, crate::PURPOSE_V4, "gocode")?;
    let signature = signer.sign(&signing_transcript(&domain, &canonical))?;
    verify_signature(&signature, trust, &domain, &canonical)?;
    Ok(SignedPromotionBootstrapV4 {
        project_owner_authority_receipt_sha256: Sha256::digest(
            canonical_checked_in_promotion_bootstrap(&unsigned, &signature)?,
        )
        .into(),
        unsigned,
        signature,
    })
}

pub(crate) fn verify_promotion_bootstrap_v3(
    value: &SignedPromotionBootstrapV4,
    trust: &VerifiedTrustConfigV3,
    predecessor: &VerifiedDocumentReconciliation,
) -> Result<(), AuthorityError> {
    let trust = trust.config();
    if trust.schema_digests != promotion_schema_pins()? {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    predecessor.authorizes_v3(trust)?;
    if value.unsigned.predecessor_receipt_sha256 != predecessor.receipt_sha256()
        || value.unsigned.trust_config_sha256 != receipt_validation::hex(&trust.sha256()?)
        || value.unsigned.key_id != receipt_validation::hex(&key_id(&trust.public_key))
        || value.unsigned.key_epoch != trust.epoch
    {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    crate::receipt_v4_validation::validate_bootstrap(&value.unsigned, trust.public_key)?;
    let canonical = canonical_unsigned_promotion_bootstrap(&value.unsigned)?;
    if value.project_owner_authority_receipt_sha256
        != Sha256::digest(canonical_checked_in_promotion_bootstrap(
            &value.unsigned,
            &value.signature,
        )?)
        .as_slice()
    {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    verify_signature(
        &value.signature,
        trust,
        &SigningDomain::new(crate::RECEIPT_SCHEMA_V4, crate::PURPOSE_V4, "gocode")?,
        &canonical,
    )
}

fn verify_signature(
    signature: &[u8; 64],
    trust: &crate::ProjectOwnerTrustConfigV3,
    domain: &SigningDomain,
    canonical: &[u8],
) -> Result<(), AuthorityError> {
    VerifyingKey::from_bytes(&trust.public_key)
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?
        .verify_strict(
            &signing_transcript(domain, canonical),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| AuthorityError::InvalidReceiptSignature)
}
