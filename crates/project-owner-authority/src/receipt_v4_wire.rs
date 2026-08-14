//! Strict raw V4 promotion-bootstrap verification boundary.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, PrevalidatedPromotionBootstrapV4, PromotionBootstrapV4,
    SignedPromotionBootstrapV4, VerifiedDocumentReconciliation, VerifiedPromotionBootstrap,
    VerifiedTrustConfigV3, canonical_checked_in_promotion_bootstrap,
    receipt_v4_v3::verify_promotion_bootstrap_v3,
};

/// Raw-only verification of canonical LF-terminated V4 bootstrap bytes.
///
/// # Errors
/// Returns a fail-closed error for duplicate, noncanonical, trust, predecessor, or signature input.
pub fn verify_promotion_bootstrap_bytes(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    trust: &VerifiedTrustConfigV3,
    predecessor: &VerifiedDocumentReconciliation,
    context: &dyn crate::PromotionBootstrapVerificationContext,
) -> Result<VerifiedPromotionBootstrap, AuthorityError> {
    crate::admit_prevalidated_promotion_bootstrap_v4(
        prevalidate_promotion_bootstrap_v4(bytes, expected_sha256, trust, predecessor)?,
        context,
    )
}

/// Verify raw promotion-bootstrap `/4` bytes without trusted-context admission.
///
/// # Errors
/// Returns canonical, digest, trust, predecessor, and signature errors only.
pub fn prevalidate_promotion_bootstrap_v4(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    trust: &VerifiedTrustConfigV3,
    predecessor: &VerifiedDocumentReconciliation,
) -> Result<PrevalidatedPromotionBootstrapV4, AuthorityError> {
    if <[u8; 32]>::from(Sha256::digest(bytes)) != expected_sha256 {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    let receipt = receipt_from_bytes(bytes)?;
    verify_promotion_bootstrap_v3(&receipt, trust, predecessor)?;
    let scope = crate::PromotionBootstrapAdmissionScope::from_bootstrap(&receipt.unsigned);
    let validity = crate::PromotionBootstrapValidity::from_bootstrap(&receipt.unsigned);
    Ok(PrevalidatedPromotionBootstrapV4 {
        bindings: crate::PromotionBootstrapBindings::from_bootstrap(&receipt.unsigned),
        receipt,
        root_public_key: trust.config().public_key,
        scope,
        validity,
    })
}

pub(crate) fn receipt_from_bytes(
    bytes: &[u8],
) -> Result<SignedPromotionBootstrapV4, AuthorityError> {
    let mut value = crate::strict_json::parse(bytes)?;
    let object = value
        .as_object_mut()
        .ok_or(AuthorityError::InvalidReceipt)?;
    let signature = signature(object.remove("signature"))?;
    for name in [
        "predecessor_receipt_sha256",
        "platform_qualified_subject_sha256",
        "platform_matrix_sha256",
        "promotion_policy_sha256",
    ] {
        hex_array(object, name)?;
    }
    let delegations = object
        .get_mut("delegations")
        .and_then(Value::as_array_mut)
        .ok_or(AuthorityError::InvalidReceipt)?;
    for delegation in delegations {
        public_key(delegation)?;
    }
    let unsigned = serde_json::from_value::<PromotionBootstrapV4>(value)
        .map_err(|_| AuthorityError::InvalidReceipt)?;
    if canonical_checked_in_promotion_bootstrap(&unsigned, &signature)? != bytes {
        return Err(AuthorityError::InvalidCanonicalReceipt);
    }
    Ok(SignedPromotionBootstrapV4 {
        project_owner_authority_receipt_sha256: Sha256::digest(bytes).into(),
        unsigned,
        signature,
    })
}

fn signature(value: Option<Value>) -> Result<[u8; 64], AuthorityError> {
    let Some(Value::String(value)) = value else {
        return Err(AuthorityError::InvalidReceipt);
    };
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?
        .try_into()
        .map_err(|_| AuthorityError::InvalidReceiptSignature)
}

fn hex_array(
    object: &mut serde_json::Map<String, Value>,
    name: &str,
) -> Result<(), AuthorityError> {
    let Some(Value::String(value)) = object.get(name) else {
        return Err(AuthorityError::InvalidReceipt);
    };
    let digest = decode_hex(value)?;
    object.insert(
        name.into(),
        Value::Array(
            digest
                .into_iter()
                .map(|item| Value::Number(item.into()))
                .collect(),
        ),
    );
    Ok(())
}

fn public_key(value: &mut Value) -> Result<(), AuthorityError> {
    let object = value
        .as_object_mut()
        .ok_or(AuthorityError::InvalidReceipt)?;
    let Some(Value::String(encoded)) = object.get("public_key") else {
        return Err(AuthorityError::InvalidReceipt);
    };
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AuthorityError::InvalidReceipt)?
        .try_into()
        .map_err(|_| AuthorityError::InvalidReceipt)?;
    object.insert(
        "public_key".into(),
        Value::Array(
            key.into_iter()
                .map(|item| Value::Number(item.into()))
                .collect(),
        ),
    );
    Ok(())
}

fn decode_hex(value: &str) -> Result<[u8; 32], AuthorityError> {
    if !crate::receipt_v4_validation::hex_digest(value) {
        return Err(AuthorityError::InvalidReceipt);
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

const fn nibble(value: u8) -> Result<u8, AuthorityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthorityError::InvalidReceipt),
    }
}
