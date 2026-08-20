//! Strict raw receipt `/5` verification against V4 trust and a verified `/4` predecessor.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, ExpectedReceiptV5Bindings, PrevalidatedPromotionAuthorityReceiptV5,
    PromotionAuthorityReceiptV5, ReceiptV5VerificationContext, SignedPromotionAuthorityReceiptV5,
    VerifiedPromotionBootstrapV5, VerifiedTrustConfigV4, framed_transcript, trust_canonical::hex,
};

const DOMAIN: &[u8] = b"gocode.project-owner.authority-receipt/5";

/// Verify canonical raw receipt `/5` bytes and mint a move-only active bootstrap.
///
/// # Errors
/// Returns before context admission for malformed, unauthentic, legacy, mixed, or divergent input.
pub fn verify_promotion_authority_receipt_v5(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    trust: &VerifiedTrustConfigV4,
    predecessor: &impl crate::PromotionBootstrapV4Lineage,
    expected: &ExpectedReceiptV5Bindings,
    context: &dyn ReceiptV5VerificationContext,
) -> Result<VerifiedPromotionBootstrapV5, AuthorityError> {
    crate::admit_prevalidated_promotion_authority_receipt_v5(
        prevalidate_promotion_authority_receipt_v5(
            bytes,
            expected_sha256,
            trust,
            predecessor,
            expected,
        )?,
        context,
    )
}

/// Verify receipt `/5` bytes without any trusted context or durable admission.
///
/// # Errors
/// Returns cryptographic, canonical, lineage, binding, or V4 pin-barrier errors.
pub fn prevalidate_promotion_authority_receipt_v5(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    trust: &VerifiedTrustConfigV4,
    predecessor: &impl crate::PromotionBootstrapV4Lineage,
    expected: &ExpectedReceiptV5Bindings,
) -> Result<PrevalidatedPromotionAuthorityReceiptV5, AuthorityError> {
    let signed = receipt_from_bytes(bytes)?;
    if signed.project_owner_authority_receipt_sha256 != expected_sha256 {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    let trust = trust.config();
    crate::verify_v4_config(trust)?;
    if trust.schema_digests != crate::v4_trust_schema_digests()? {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    crate::receipt_v5_validation::validate(
        &signed.unsigned,
        trust,
        &crate::v5_lineage::v4_lineage(predecessor),
    )?;
    if signed.unsigned.production_security_review_sha256
        != expected.production_security_review_sha256
        || signed.unsigned.subject != expected.subject
        || signed.unsigned.destination_allowlist_sha256
            != expected.destination_allowlist_unsigned_sha256
        || signed.unsigned.destination_allowlist_generation
            != expected.destination_allowlist_generation
    {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    VerifyingKey::from_bytes(&trust.public_key)
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?
        .verify_strict(
            &framed_transcript(DOMAIN, &canonical_unsigned_receipt_v5(&signed.unsigned)?)?,
            &Signature::from_bytes(&signed.signature),
        )
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?;
    Ok(PrevalidatedPromotionAuthorityReceiptV5 {
        receipt_sha256: expected_sha256,
        unsigned: signed.unsigned,
        root_public_key: trust.public_key,
    })
}

/// Encode the signed receipt fields as exact canonical unsigned bytes.
///
/// # Errors
/// Returns an error only when serialization fails.
pub fn canonical_unsigned_receipt_v5(
    value: &PromotionAuthorityReceiptV5,
) -> Result<Vec<u8>, AuthorityError> {
    let mut root = serde_json::to_value(value).map_err(|_| AuthorityError::Serialization)?;
    rewrite_receipt(&mut root)?;
    encode(&root)
}

/// Encode exact canonical checked-in receipt bytes including its detached signature.
///
/// # Errors
/// Returns an error only when serialization fails.
pub fn canonical_checked_in_receipt_v5(
    value: &PromotionAuthorityReceiptV5,
    signature: &[u8; 64],
) -> Result<Vec<u8>, AuthorityError> {
    let mut root = serde_json::to_value(value).map_err(|_| AuthorityError::Serialization)?;
    rewrite_receipt(&mut root)?;
    root.as_object_mut()
        .ok_or(AuthorityError::Serialization)?
        .insert(
            "signature".into(),
            Value::String(URL_SAFE_NO_PAD.encode(signature)),
        );
    encode(&root)
}

fn receipt_from_bytes(bytes: &[u8]) -> Result<SignedPromotionAuthorityReceiptV5, AuthorityError> {
    let mut root = crate::strict_json::parse(bytes)?;
    let signature = root
        .as_object_mut()
        .and_then(|object| object.remove("signature"))
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(AuthorityError::InvalidReceipt)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?
        .try_into()
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?;
    parse_receipt_arrays(&mut root)?;
    let unsigned = serde_json::from_value(root).map_err(|_| AuthorityError::InvalidReceipt)?;
    if canonical_checked_in_receipt_v5(&unsigned, &signature)? != bytes {
        return Err(AuthorityError::InvalidCanonicalReceipt);
    }
    Ok(SignedPromotionAuthorityReceiptV5 {
        project_owner_authority_receipt_sha256: Sha256::digest(bytes).into(),
        unsigned,
        signature,
    })
}

fn parse_receipt_arrays(root: &mut Value) -> Result<(), AuthorityError> {
    let object = root.as_object_mut().ok_or(AuthorityError::InvalidReceipt)?;
    for field in [
        "predecessor_receipt_sha256",
        "platform_qualified_subject_sha256",
        "platform_matrix_sha256",
        "production_security_review_sha256",
        "promotion_policy_sha256",
        "adr_0029_sha256",
        "post_rc0_program_sha256",
        "destination_allowlist_sha256",
    ] {
        rewrite_hex(object, field)?;
    }
    for field in ["transition_delegations", "evidence_delegations"] {
        for item in object
            .get_mut(field)
            .and_then(Value::as_array_mut)
            .ok_or(AuthorityError::InvalidReceipt)?
        {
            let item = item.as_object_mut().ok_or(AuthorityError::InvalidReceipt)?;
            let key = item
                .get("public_key")
                .and_then(Value::as_str)
                .ok_or(AuthorityError::InvalidReceipt)?;
            let key: [u8; 32] = URL_SAFE_NO_PAD
                .decode(key)
                .map_err(|_| AuthorityError::InvalidReceipt)?
                .try_into()
                .map_err(|_| AuthorityError::InvalidReceipt)?;
            item.insert(
                "public_key".into(),
                Value::Array(key.into_iter().map(Into::into).collect()),
            );
        }
    }
    Ok(())
}

fn rewrite_hex(
    object: &mut serde_json::Map<String, Value>,
    name: &str,
) -> Result<(), AuthorityError> {
    let value = object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(AuthorityError::InvalidReceipt)?;
    if !crate::receipt_v4_validation::hex_digest(value) {
        return Err(AuthorityError::InvalidReceipt);
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    object.insert(
        name.into(),
        Value::Array(output.into_iter().map(Into::into).collect()),
    );
    Ok(())
}

fn rewrite_receipt(root: &mut Value) -> Result<(), AuthorityError> {
    let object = root.as_object_mut().ok_or(AuthorityError::Serialization)?;
    for field in [
        "predecessor_receipt_sha256",
        "platform_qualified_subject_sha256",
        "platform_matrix_sha256",
        "production_security_review_sha256",
        "promotion_policy_sha256",
        "adr_0029_sha256",
        "post_rc0_program_sha256",
        "destination_allowlist_sha256",
    ] {
        rewrite_array_hex(object, field)?;
    }
    for field in ["transition_delegations", "evidence_delegations"] {
        for item in object
            .get_mut(field)
            .and_then(Value::as_array_mut)
            .ok_or(AuthorityError::Serialization)?
        {
            let item = item.as_object_mut().ok_or(AuthorityError::Serialization)?;
            let key = array(
                item.get("public_key")
                    .ok_or(AuthorityError::Serialization)?,
            )?;
            item.insert(
                "public_key".into(),
                Value::String(URL_SAFE_NO_PAD.encode(key)),
            );
        }
    }
    Ok(())
}

fn rewrite_array_hex(
    object: &mut serde_json::Map<String, Value>,
    name: &str,
) -> Result<(), AuthorityError> {
    let value = array(object.get(name).ok_or(AuthorityError::Serialization)?)?;
    object.insert(name.into(), Value::String(hex(&value)));
    Ok(())
}
fn array(value: &Value) -> Result<[u8; 32], AuthorityError> {
    value
        .as_array()
        .ok_or(AuthorityError::Serialization)?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(AuthorityError::Serialization)
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| AuthorityError::Serialization)
}
const fn nibble(value: u8) -> Result<u8, AuthorityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthorityError::InvalidReceipt),
    }
}
fn encode(value: &Value) -> Result<Vec<u8>, AuthorityError> {
    let mut bytes = serde_json::to_vec(
        &value
            .as_object()
            .ok_or(AuthorityError::Serialization)?
            .iter()
            .collect::<BTreeMap<_, _>>(),
    )
    .map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}
