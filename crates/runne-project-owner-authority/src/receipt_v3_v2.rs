//! Production V3 reconciliation receipts signed only by V2 trust.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, Document, DocumentBinding, GitSubject, ProjectOwnerSignature, SignedReceiptV3,
    Signer, SigningDomain, UnsignedReceiptV3, VerifiedInitialAuthorization, VerifiedTrustConfigV2,
    canonical_checked_in_receipt_v3, canonical_unsigned_receipt_v3, key_id,
    receipt_v3::{PROFILE_V3, PURPOSE, PurposeProfileV3, RECEIPT_SCHEMA_V3, REPOSITORY, ROLE},
    receipt_v3_codec::{binding, validate},
    receipt_validation, signing_transcript,
};

/// Sign a production V3 receipt with a verified V2 successor trust configuration.
///
/// # Errors
/// Returns a fail-closed error for an unverified V2 trust, pins, bindings, or signer mismatch.
pub fn sign_receipt_v3_v2(
    profile: &PurposeProfileV3,
    trust: &VerifiedTrustConfigV2,
    predecessor: &VerifiedInitialAuthorization,
    subject: GitSubject,
    mut documents: Vec<DocumentBinding>,
    issued_at: String,
    signer: &dyn Signer,
) -> Result<SignedReceiptV3, AuthorityError> {
    let trust = trust.config();
    profile.validate_trust_v2(trust)?;
    predecessor.authorizes_v2(trust)?;
    validate(profile, &documents, &subject)?;
    if !receipt_validation::valid_timestamp(&issued_at) {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    documents.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let unsigned = unsigned(trust, predecessor, subject, documents, issued_at)?;
    let canonical = canonical_unsigned_receipt_v3(&unsigned)?;
    let domain = SigningDomain::new(RECEIPT_SCHEMA_V3, PURPOSE, REPOSITORY)?;
    let signature = signer.sign(&signing_transcript(&domain, &canonical))?;
    verify_signature(&signature, trust, &domain, &canonical)?;
    let digest = Sha256::digest(canonical_checked_in_receipt_v3(&unsigned, &signature)?).into();
    Ok(SignedReceiptV3 {
        project_owner_authority_receipt_sha256: digest,
        predecessor_receipt_sha256: predecessor.digest(),
        unsigned,
        signature,
    })
}

/// Verify a production V3 receipt against V2 trust only.
///
/// # Errors
/// Returns a fail-closed error for V1-shaped trust, pins, bindings, or signature mismatch.
pub fn verify_receipt_v3_v2(
    receipt: &SignedReceiptV3,
    profile: &PurposeProfileV3,
    trust: &VerifiedTrustConfigV2,
    predecessor: &VerifiedInitialAuthorization,
) -> Result<(), AuthorityError> {
    let trust = trust.config();
    profile.validate_trust_v2(trust)?;
    predecessor.authorizes_v2(trust)?;
    let fields = &receipt.unsigned;
    if receipt.predecessor_receipt_sha256 != predecessor.digest()
        || fields.predecessor_receipt_sha256 != predecessor.digest()
        || fields.schema_version != RECEIPT_SCHEMA_V3
        || fields.repository_id != REPOSITORY
        || fields.role != ROLE
        || fields.purpose != PURPOSE
        || fields.profile != PROFILE_V3
        || fields.key_id != receipt_validation::hex(&key_id(&trust.public_key))
        || fields.key_epoch != trust.epoch
        || fields.trust_config_sha256 != receipt_validation::hex(&trust.sha256()?)
        || !receipt_validation::valid_timestamp(&fields.issued_at)
    {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    let bindings = fields
        .documents
        .iter()
        .cloned()
        .map(binding)
        .collect::<Vec<_>>();
    validate(profile, &bindings, &fields.subject)?;
    let canonical = canonical_unsigned_receipt_v3(fields)?;
    if receipt.project_owner_authority_receipt_sha256
        != Sha256::digest(canonical_checked_in_receipt_v3(fields, &receipt.signature)?).as_slice()
    {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    verify_signature(
        &receipt.signature,
        trust,
        &SigningDomain::new(RECEIPT_SCHEMA_V3, PURPOSE, REPOSITORY)?,
        &canonical,
    )
}

fn unsigned(
    trust: &crate::ProjectOwnerTrustConfigV2,
    predecessor: &VerifiedInitialAuthorization,
    subject: GitSubject,
    documents: Vec<DocumentBinding>,
    issued_at: String,
) -> Result<UnsignedReceiptV3, AuthorityError> {
    Ok(UnsignedReceiptV3 {
        schema_version: RECEIPT_SCHEMA_V3.into(),
        repository_id: REPOSITORY.into(),
        role: ROLE.into(),
        purpose: PURPOSE.into(),
        trust_config_sha256: receipt_validation::hex(&trust.sha256()?),
        key_id: receipt_validation::hex(&key_id(&trust.public_key)),
        key_epoch: trust.epoch,
        subject,
        documents: documents
            .into_iter()
            .map(|item| Document {
                path: item.path,
                mode: item.mode,
                blob_oid: item.blob_oid,
                content_sha256: item.content_sha256,
                byte_length: item.byte_length,
                schema_id: item.schema_id,
            })
            .collect(),
        issued_at,
        profile: PROFILE_V3.into(),
        predecessor_receipt_sha256: predecessor.digest(),
    })
}
fn verify_signature(
    signature: &ProjectOwnerSignature,
    trust: &crate::ProjectOwnerTrustConfigV2,
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
