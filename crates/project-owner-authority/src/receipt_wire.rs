//! Strict raw checked-in receipt parsing and byte-bound verification.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, GitSubject, ProjectOwnerSignature, ProjectOwnerTrustConfigV1, PurposeProfileV1,
    SignedReceipt, TrustAnchorState, UnsignedReceipt, canonical_checked_in_receipt,
    receipt::{DocumentBinding, verify_receipt},
};

/// Strictly parsed but unauthenticated checked-in receipt fields.
///
/// This value is inspection-only and does not establish trust, signature validity, or authority.
/// Treat it as untrusted until [`verify_receipt_bytes_against_subject`] succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedReceipt {
    subject: GitSubject,
    documents: Vec<DocumentBinding>,
    checked_in_sha256: [u8; 32],
}

impl InspectedReceipt {
    /// Return the strictly parsed but unauthenticated Git subject.
    #[must_use]
    pub const fn subject(&self) -> &GitSubject {
        &self.subject
    }

    /// Return strictly parsed but unauthenticated canonical document bindings.
    #[must_use]
    pub fn documents(&self) -> &[DocumentBinding] {
        &self.documents
    }

    /// Return the SHA-256 of the exact canonical checked-in receipt bytes.
    #[must_use]
    pub const fn checked_in_sha256(&self) -> [u8; 32] {
        self.checked_in_sha256
    }
}

/// Strictly inspect exact canonical checked-in receipt bytes without authenticating them.
///
/// The returned data is untrusted until [`verify_receipt_bytes_against_subject`] succeeds.
///
/// # Errors
///
/// Returns a fail-closed error for duplicate, unknown, malformed, or noncanonical receipt bytes.
pub fn inspect_receipt_bytes(bytes: &[u8]) -> Result<InspectedReceipt, AuthorityError> {
    let receipt = receipt_from_bytes(bytes)?;
    Ok(InspectedReceipt {
        subject: receipt.unsigned.subject,
        documents: receipt
            .unsigned
            .documents
            .into_iter()
            .map(DocumentBinding::from_document)
            .collect(),
        checked_in_sha256: receipt.project_owner_authority_receipt_sha256,
    })
}

/// Verify supplied checked-in bytes, rejecting every noncanonical representation.
///
/// This is the byte-bound public verifier. It accepts only strict JSON whose exact bytes equal
/// canonical checked-in bytes, so CRLF, whitespace, key-order, duplicate, and unknown changes
/// cannot alter the receipt digest's authority meaning.
///
/// # Errors
///
/// Returns a fail-closed parse, canonical-byte, digest, trust, or signature error.
pub fn verify_receipt_bytes(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    profile: &PurposeProfileV1,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
) -> Result<(), AuthorityError> {
    if <[u8; 32]>::from(Sha256::digest(bytes)) != expected_sha256 {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    let receipt = receipt_from_bytes(bytes)?;
    verify_receipt(&receipt, profile, trust, anchor)
}

/// Verify receipt bytes and bind them to one exact captured subject and document sequence.
///
/// # Errors
///
/// Returns a fail-closed error for raw receipt failure or any subject/binding mismatch.
pub fn verify_receipt_bytes_against_subject(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    profile: &PurposeProfileV1,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
    expected_subject: &crate::GitSubject,
    expected_documents: &[DocumentBinding],
) -> Result<[u8; 32], AuthorityError> {
    verify_receipt_bytes(bytes, expected_sha256, profile, trust, anchor)?;
    let receipt = receipt_from_bytes(bytes)?;
    if receipt.unsigned.subject != *expected_subject {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    let documents = receipt
        .unsigned
        .documents
        .iter()
        .cloned()
        .map(DocumentBinding::from_document)
        .collect::<Vec<_>>();
    if !strictly_sorted(expected_documents) || documents != expected_documents {
        return Err(AuthorityError::InvalidDocumentBinding);
    }
    Ok(expected_sha256)
}

fn receipt_from_bytes(bytes: &[u8]) -> Result<SignedReceipt, AuthorityError> {
    let mut value = crate::strict_json::parse(bytes)?;
    let object = value
        .as_object_mut()
        .ok_or(AuthorityError::InvalidReceipt)?;
    let signature = decode_signature(object.remove("signature"))?;
    let unsigned = UnsignedReceipt::from_json(
        &serde_json::to_vec(&value).map_err(|_| AuthorityError::Serialization)?,
    )?;
    let canonical = canonical_checked_in_receipt(&unsigned, &signature)?;
    if canonical != bytes {
        return Err(AuthorityError::InvalidCanonicalReceipt);
    }
    Ok(SignedReceipt {
        unsigned,
        signature,
        project_owner_authority_receipt_sha256: Sha256::digest(bytes).into(),
    })
}

fn strictly_sorted(documents: &[DocumentBinding]) -> bool {
    documents
        .windows(2)
        .all(|pair| pair[0].path.as_bytes() < pair[1].path.as_bytes())
}

fn decode_signature(value: Option<Value>) -> Result<ProjectOwnerSignature, AuthorityError> {
    let Some(Value::String(encoded)) = value else {
        return Err(AuthorityError::InvalidReceipt);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?;
    bytes
        .try_into()
        .map_err(|_| AuthorityError::InvalidReceiptSignature)
}
