//! Strict root-signed publication destination-allowlist `/1` verification.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, DESTINATION_ALLOWLIST_SCHEMA_V1, DestinationAllowlistAdmissionScope,
    DestinationAllowlistVerificationContext, PrevalidatedDestinationAllowlistV1,
    PrevalidatedRootSignedDestinationAllowlistV1, PublicationDestinationAllowlistV1,
    VerifiedDestinationAllowlist, VerifiedPromotionBootstrapV5, VerifiedTrustConfigV4,
    canonical_checked_in_allowlist_v1, canonical_unsigned_allowlist_v1, framed_transcript,
    receipt_validation::valid_timestamp, trust_canonical::hex,
};

/// Length-framed domain separation for allowlist `/1` root detached signatures.
const DOMAIN_V1: &[u8] = b"runne.project-owner.publication-destination-allowlist/1";
/// Verify canonical raw allowlist `/1` bytes and mint a move-only handle.
///
/// The V4 root key identity and the receipt `/5` initial digest/generation are
/// bound before the trusted allowlist context is called.
///
/// # Errors
/// Returns `AUTHORITY_VERSION_SUPERSEDED` for legacy/mixed versions, rejects
/// noncanonical, unauthentic, or divergent input before context admission, and
/// propagates trusted-context admission failures.
pub fn verify_destination_allowlist_v1(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    trust4: &VerifiedTrustConfigV4,
    receipt5: &VerifiedPromotionBootstrapV5,
    context: &dyn DestinationAllowlistVerificationContext,
) -> Result<VerifiedDestinationAllowlist, AuthorityError> {
    crate::admit_prevalidated_destination_allowlist_v1(
        prevalidate_destination_allowlist_v1(bytes, expected_sha256, trust4, receipt5)?,
        context,
    )
}
/// Prevalidate allowlist `/1` bytes without trusted-context admission.
///
/// # Errors
/// Returns canonical, digest, pin, signature, lineage, or binding errors.
pub fn prevalidate_destination_allowlist_v1(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    trust4: &VerifiedTrustConfigV4,
    receipt5: &impl crate::PromotionAuthorityReceiptV5Lineage,
) -> Result<PrevalidatedDestinationAllowlistV1, AuthorityError> {
    bind_prevalidated_destination_allowlist_v1(
        prevalidate_root_signed_destination_allowlist_v1(bytes, expected_sha256, trust4)?,
        receipt5,
    )
}

/// Verify allowlist canonical bytes and root signature without receipt binding or admission.
///
/// # Errors
/// Returns canonical, digest, root-key, validity, or signature errors.
pub fn prevalidate_root_signed_destination_allowlist_v1(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    trust4: &VerifiedTrustConfigV4,
) -> Result<PrevalidatedRootSignedDestinationAllowlistV1, AuthorityError> {
    let (value, signature) = allowlist_from_bytes(bytes)?;
    let canonical = bytes
        .strip_suffix(b"\n")
        .ok_or(AuthorityError::InvalidCanonicalReceipt)?;
    if <[u8; 32]>::from(Sha256::digest(canonical)) != expected_sha256 {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    let unsigned = canonical_unsigned_allowlist_v1(&value)?;
    if value.key_id != hex(&crate::key_id(&trust4.public_key)) || value.key_epoch != trust4.epoch {
        return Err(AuthorityError::InvalidDestinationAllowlist);
    }
    validate(&value)?;
    VerifyingKey::from_bytes(&trust4.public_key)
        .map_err(|_| AuthorityError::InvalidDestinationAllowlist)?
        .verify_strict(
            &framed_transcript(DOMAIN_V1, &unsigned)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?;
    Ok(PrevalidatedRootSignedDestinationAllowlistV1 {
        digest: expected_sha256,
        unsigned_sha256: Sha256::digest(&unsigned).into(),
        root_public_key: trust4.public_key,
        value,
    })
}

/// Bind a root-signature-verified allowlist to receipt `/5` without admission.
///
/// # Errors
/// Returns an error unless the unsigned instance digest, generation, and root are exact.
pub fn bind_prevalidated_destination_allowlist_v1(
    root_signed: PrevalidatedRootSignedDestinationAllowlistV1,
    receipt5: &impl crate::PromotionAuthorityReceiptV5Lineage,
) -> Result<PrevalidatedDestinationAllowlistV1, AuthorityError> {
    let lineage = crate::v5_lineage::v5_lineage(receipt5);
    if root_signed.value.generation != lineage.bindings.destination_allowlist_generation()
        || root_signed.unsigned_sha256 != lineage.bindings.destination_allowlist_sha256()
        || root_signed.root_public_key != lineage.root_public_key
    {
        return Err(AuthorityError::InvalidDestinationAllowlist);
    }
    let value = root_signed.value;
    Ok(PrevalidatedDestinationAllowlistV1 {
        digest: root_signed.digest,
        unsigned_sha256: root_signed.unsigned_sha256,
        scope: DestinationAllowlistAdmissionScope {
            allowlist_sha256: root_signed.digest,
            unsigned_sha256: root_signed.unsigned_sha256,
            generation: value.generation,
            receipt_sha256: lineage.receipt_sha256,
            trust_config_sha256: lineage.bindings.trust_config_sha256().into(),
            trust_generation: lineage.bindings.trust_generation(),
            root_public_key: lineage.root_public_key,
            root_principal_id: lineage.root_identity.principal_id().into(),
            root_controlling_account_id: lineage.root_identity.account_id().into(),
            root_lane_id: lineage.root_identity.lane_id().into(),
            root_signature_profile_id: lineage.root_identity.signature_profile_id().into(),
            root_key_id: value.key_id.clone(),
            root_key_epoch: value.key_epoch,
            root_revocation_epoch: value.revocation_epoch,
            policy_id: value.policy_id.clone(),
            not_before: value.not_before.clone(),
            expires_at: value.expires_at.clone(),
            role_scope_floors: crate::v5_state_validation::floors(
                lineage.transition_delegations,
                lineage.evidence_delegations,
            ),
        },
        value,
    })
}

fn validate(value: &PublicationDestinationAllowlistV1) -> Result<(), AuthorityError> {
    if value.schema_version != DESTINATION_ALLOWLIST_SCHEMA_V1
        || value.repository_id != "runne"
        || value.generation == 0
        || value.revocation_epoch == 0
        || !valid_identifier(&value.policy_id, 128)
        || !ordered(&value.issued_at, &value.not_before, &value.expires_at)
        || value.destinations.is_empty()
    {
        return Err(AuthorityError::InvalidDestinationAllowlist);
    }
    let mut previous: Option<(&str, &str)> = None;
    for item in &value.destinations {
        let key = (item.destination.as_str(), item.channel.as_str());
        if !valid_identifier(&item.destination, 512)
            || !valid_identifier(&item.channel, 128)
            || !valid_effect_kinds(&item.permitted_effect_kinds)
            || previous.is_some_and(|previous| previous >= key)
        {
            return Err(AuthorityError::InvalidDestinationAllowlist);
        }
        previous = Some(key);
    }
    Ok(())
}

fn valid_effect_kinds(kinds: &[String]) -> bool {
    !kinds.is_empty()
        && kinds.windows(2).all(|pair| pair[0] < pair[1])
        && kinds.iter().all(|kind| valid_identifier(kind, 128))
}

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn ordered(first: &str, second: &str, third: &str) -> bool {
    valid_timestamp(first)
        && valid_timestamp(second)
        && valid_timestamp(third)
        && first < second
        && second < third
}

fn allowlist_from_bytes(
    bytes: &[u8],
) -> Result<(PublicationDestinationAllowlistV1, [u8; 64]), AuthorityError> {
    let mut value = crate::strict_json::parse(bytes)?;
    if value
        .as_object()
        .and_then(|object| object.get("schema_version"))
        .and_then(Value::as_str)
        != Some(DESTINATION_ALLOWLIST_SCHEMA_V1)
    {
        return Err(AuthorityError::AuthorityVersionSuperseded);
    }
    let object = value
        .as_object_mut()
        .ok_or(AuthorityError::InvalidDestinationAllowlist)?;
    let signature = signature(object.remove("signature"))?;
    for item in object
        .get_mut("destinations")
        .and_then(Value::as_array_mut)
        .ok_or(AuthorityError::InvalidDestinationAllowlist)?
    {
        let item = item
            .as_object_mut()
            .ok_or(AuthorityError::InvalidDestinationAllowlist)?;
        hex_array(item, "executor_policy_sha256")?;
    }
    let value = serde_json::from_value::<PublicationDestinationAllowlistV1>(value)
        .map_err(|_| AuthorityError::InvalidDestinationAllowlist)?;
    if canonical_checked_in_allowlist_v1(&value, &signature)? != bytes {
        return Err(AuthorityError::InvalidCanonicalReceipt);
    }
    Ok((value, signature))
}

fn signature(value: Option<Value>) -> Result<[u8; 64], AuthorityError> {
    let Some(Value::String(value)) = value else {
        return Err(AuthorityError::InvalidDestinationAllowlist);
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
        return Err(AuthorityError::InvalidDestinationAllowlist);
    };
    if !crate::receipt_v4_validation::hex_digest(value) {
        return Err(AuthorityError::InvalidDestinationAllowlist);
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    object.insert(
        name.into(),
        Value::Array(output.into_iter().map(Into::into).collect()),
    );
    Ok(())
}

const fn nibble(value: u8) -> Result<u8, AuthorityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthorityError::InvalidDestinationAllowlist),
    }
}
