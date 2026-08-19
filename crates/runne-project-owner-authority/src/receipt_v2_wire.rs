//! Strict raw checked-in receipt parsing and v2 byte-bound verification.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, ProjectOwnerSignature, ProjectOwnerTrustConfigV1, PurposeProfileV2,
    SignedReceipt, TrustAnchorState, UnsignedReceipt, canonical_checked_in_receipt,
    verify_receipt_v2,
};

/// Verify supplied v2 checked-in bytes, rejecting every noncanonical representation.
///
/// # Errors
///
/// Returns a fail-closed parse, canonical-byte, digest, trust, or signature error.
pub fn verify_receipt_v2_bytes(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    profile: &PurposeProfileV2,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
) -> Result<(), AuthorityError> {
    if <[u8; 32]>::from(Sha256::digest(bytes)) != expected_sha256 {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    verify_receipt_v2(&receipt_from_bytes(bytes)?, profile, trust, anchor)
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
    if canonical_checked_in_receipt(&unsigned, &signature)? != bytes {
        return Err(AuthorityError::InvalidCanonicalReceipt);
    }
    Ok(SignedReceipt {
        unsigned,
        signature,
        project_owner_authority_receipt_sha256: Sha256::digest(bytes).into(),
    })
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
