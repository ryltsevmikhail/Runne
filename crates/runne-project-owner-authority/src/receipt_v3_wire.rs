//! Strict raw checked-in receipt parsing and v3 byte-bound verification.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, FixtureVerifiedDocumentReconciliation, ProjectOwnerSignature,
    ProjectOwnerTrustConfigV1, PurposeProfileV3, SignedReceiptV3, TrustAnchorState,
    UnsignedReceiptV3, VerifiedInitialAuthorization,
    receipt_v3::fixture_verified_document_reconciliation,
    receipt_v3_codec::{canonical_checked_in_receipt_v3, verify_receipt_v3},
};

/// Verify supplied v3 checked-in bytes, rejecting every noncanonical representation.
///
/// # Errors
/// Returns a fail-closed parse, canonical-byte, digest, trust, predecessor, or signature error.
pub fn verify_receipt_v3_fixture_bytes(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    profile: &PurposeProfileV3,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
    predecessor: &VerifiedInitialAuthorization,
) -> Result<FixtureVerifiedDocumentReconciliation, AuthorityError> {
    if <[u8; 32]>::from(Sha256::digest(bytes)) != expected_sha256 {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    verify_receipt_v3(
        &receipt_from_bytes(bytes)?,
        profile,
        trust,
        anchor,
        predecessor,
    )?;
    Ok(fixture_verified_document_reconciliation(expected_sha256))
}

pub fn receipt_from_bytes(bytes: &[u8]) -> Result<SignedReceiptV3, AuthorityError> {
    let mut value = crate::strict_json::parse(bytes)?;
    let object = value
        .as_object_mut()
        .ok_or(AuthorityError::InvalidReceipt)?;
    let signature = decode_signature(object.remove("signature"))?;
    let predecessor = object
        .get("predecessor_receipt_sha256")
        .and_then(Value::as_str)
        .ok_or(AuthorityError::InvalidReceipt)?;
    object.insert(
        "predecessor_receipt_sha256".into(),
        Value::Array(
            decode_digest(predecessor)?
                .into_iter()
                .map(|byte| Value::Number(byte.into()))
                .collect(),
        ),
    );
    let unsigned = serde_json::from_value::<UnsignedReceiptV3>(value)
        .map_err(|_| AuthorityError::InvalidReceipt)?;
    if canonical_checked_in_receipt_v3(&unsigned, &signature)? != bytes {
        return Err(AuthorityError::InvalidCanonicalReceipt);
    }
    Ok(SignedReceiptV3 {
        project_owner_authority_receipt_sha256: Sha256::digest(bytes).into(),
        predecessor_receipt_sha256: unsigned.predecessor_receipt_sha256,
        unsigned,
        signature,
    })
}

fn decode_signature(value: Option<Value>) -> Result<ProjectOwnerSignature, AuthorityError> {
    let Some(Value::String(encoded)) = value else {
        return Err(AuthorityError::InvalidReceipt);
    };
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?
        .try_into()
        .map_err(|_| AuthorityError::InvalidReceiptSignature)
}

fn decode_digest(value: &str) -> Result<[u8; 32], AuthorityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AuthorityError::InvalidReceipt);
    }
    let mut result = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        result[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Ok(result)
}

const fn hex(byte: u8) -> Result<u8, AuthorityError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AuthorityError::InvalidReceipt),
    }
}
