//! Strict raw stage-envelope verification.

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::stage_envelope_wire_codec::{hex_array, signature};
use crate::{
    AuthorityError, StageAuthorityEnvelopeV1, VerifiedPromotionBootstrap, VerifiedStageEnvelope,
    canonical_checked_in_stage_envelope, canonical_stage_payload, promotion_schema_pins,
    receipt_v4_validation::safe_id, signing_transcript,
};

/// # Errors
/// Returns an error for noncanonical or unauthentic raw envelope bytes.
pub fn verify_stage_envelope_bytes(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    bootstrap: &VerifiedPromotionBootstrap,
    _: &dyn crate::StageVerificationContext,
) -> Result<VerifiedStageEnvelope, AuthorityError> {
    verify(bytes, expected_sha256, bootstrap, &PureStageContext, None)
}
struct PureStageContext;
impl crate::StageVerificationContext for PureStageContext {
    fn admit_or_recover(
        &self,
        _: &crate::StageAdmissionRequest<'_>,
    ) -> Result<crate::StageAdmission, AuthorityError> {
        Ok(crate::StageAdmission::NewlyAdmitted)
    }
}

/// # Errors
/// Returns an error for a divergent reservation, raw bytes, or authority context.
pub fn verify_stage_envelope_for_transition(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    bootstrap: &VerifiedPromotionBootstrap,
    context: &dyn crate::StageVerificationContext,
    reservation: gocode_promotion_contracts::StageTransitionReservation,
) -> Result<VerifiedStageEnvelope, AuthorityError> {
    verify(
        bytes,
        expected_sha256,
        bootstrap,
        context,
        Some(reservation),
    )
}

fn verify(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    bootstrap: &VerifiedPromotionBootstrap,
    context: &dyn crate::StageVerificationContext,
    reservation: Option<gocode_promotion_contracts::StageTransitionReservation>,
) -> Result<VerifiedStageEnvelope, AuthorityError> {
    let (value, signature) = envelope_from_bytes(bytes)?;
    if value.payload_schema_id == "gocode.release.rc3-publication-authorization/1" {
        return Err(AuthorityError::AuthorityVersionSuperseded);
    }
    let canonical_envelope = bytes
        .strip_suffix(b"\n")
        .ok_or(AuthorityError::InvalidCanonicalReceipt)?;
    if <[u8; 32]>::from(Sha256::digest(canonical_envelope)) != expected_sha256 {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    crate::stage_envelope::validate_stage_fields(&value)?;
    if value.bootstrap_receipt_sha256 != bootstrap.receipt_sha256()
        || value.issuer_key_id
            == crate::receipt_validation::hex(&crate::key_id(&bootstrap.root_public_key()))
    {
        return Err(AuthorityError::InvalidStageEnvelope);
    }
    let delegation = bootstrap
        .delegation(&value.issuer_role)
        .ok_or(AuthorityError::InvalidStageEnvelope)?;
    let within_delegation_window = [
        value.issued_at >= delegation.not_before,
        value.not_before >= delegation.not_before,
        value.expires_at <= delegation.expires_at,
    ]
    .into_iter()
    .all(std::convert::identity);
    if value.issuer_principal_id != delegation.principal_id
        || value.issuer_controlling_account_id != delegation.controlling_account_id
        || value.issuer_lane_id != delegation.lane_id
        || value.issuer_key_id != delegation.key_id
        || value.issuer_key_epoch != delegation.key_epoch
        || value.signature_profile_id != delegation.signature_profile_id
        || value.revocation_epoch != delegation.revocation_epoch
        || delegation.allowed_payload_schema_ids
            != crate::receipt_v4_validation::allowed(&value.issuer_role)
        || value.payload_schema_id.as_str() != delegation.allowed_payload_schema_ids[0].as_str()
        || !within_delegation_window
        || !safe_id(&value.issuer_principal_id)
    {
        return Err(AuthorityError::InvalidStageEnvelope);
    }
    let pins = promotion_schema_pins()?;
    if pins
        .iter()
        .find(|pin| pin.schema_id == value.payload_schema_id)
        .map(|pin| pin.schema_sha256)
        != Some(value.payload_schema_sha256)
        || <[u8; 32]>::from(Sha256::digest(canonical_stage_payload(&value.payload)?))
            != value.payload_sha256
    {
        return Err(AuthorityError::InvalidStageEnvelope);
    }
    let domain = crate::SigningDomain::new(
        crate::STAGE_ENVELOPE_SCHEMA_V1,
        &value.issuer_role,
        "gocode",
    )?;
    VerifyingKey::from_bytes(&delegation.public_key)
        .map_err(|_| AuthorityError::InvalidStageEnvelope)?
        .verify_strict(
            &signing_transcript(&domain, &crate::canonical_unsigned_stage_envelope(&value)?),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?;
    let payload = canonical_stage_payload(&value.payload)?;
    admit_and_mint(
        value,
        payload,
        expected_sha256,
        bootstrap,
        context,
        reservation,
    )
}

fn admit_and_mint(
    value: StageAuthorityEnvelopeV1,
    payload: Vec<u8>,
    expected_sha256: [u8; 32],
    bootstrap: &VerifiedPromotionBootstrap,
    context: &dyn crate::StageVerificationContext,
    reservation: Option<gocode_promotion_contracts::StageTransitionReservation>,
) -> Result<VerifiedStageEnvelope, AuthorityError> {
    let typed =
        gocode_promotion_contracts::validate_stage_payload(&value.payload_schema_id, &payload)
            .map_err(|_| AuthorityError::InvalidStageEnvelope)?;
    if reservation
        .as_ref()
        .is_some_and(|scope| scope.kind() != typed.kind())
    {
        return Err(AuthorityError::InvalidStageEnvelope);
    }
    let legacy = gocode_promotion_contracts::StageTransitionReservation::new(
        "legacy".into(),
        0,
        "legacy".into(),
        typed.kind(),
        [0; 32],
    )
    .expect("hard-coded legacy scope is canonical");
    let bound = reservation.as_ref().unwrap_or(&legacy);
    let validity = typed_payload_validity(&payload, value.revocation_epoch)?;
    let verified_admission = {
        let request = crate::StageAdmissionRequest {
            bootstrap_validity: bootstrap.validity(),
            bootstrap_admission_scope: bootstrap.admission_scope(),
            scope: crate::StageAdmissionScope {
                reservation: bound,
                bootstrap_receipt_sha256: value.bootstrap_receipt_sha256,
                role: &value.issuer_role,
                payload_sha256: value.payload_sha256,
                authorization_nonce: &value.authorization_nonce,
                envelope_sha256: expected_sha256,
            },
            envelope_not_before: &value.not_before,
            envelope_expires_at: &value.expires_at,
            envelope_revocation_epoch: value.revocation_epoch,
            payload_valid_from: validity.0,
            payload_expires_at: validity.1,
            payload_revocation_epoch: validity.2,
        };
        let verified_admission = crate::VerifiedStageAdmission::new(&request);
        context
            .admit_or_recover(&request)
            .map_err(|error| match error {
                AuthorityError::ReplayedStageEnvelope
                | AuthorityError::StaleOrRevokedStageEnvelope => error,
                _ => AuthorityError::StageVerificationContextRequired,
            })?;
        verified_admission
    };
    let admission = reservation.map(|reservation| verified_admission.with_reservation(reservation));
    Ok(crate::stage_envelope::verified_stage_envelope(
        expected_sha256,
        value.payload_sha256,
        value.payload_schema_id,
        payload,
        (
            crate::VerifiedStageIssuer {
                principal: value.issuer_principal_id,
                account: value.issuer_controlling_account_id,
                lane: value.issuer_lane_id,
                key: value.issuer_key_id,
                signature_profile: value.signature_profile_id,
            },
            bootstrap.root_identity().clone(),
        ),
        value.bootstrap_receipt_sha256,
        admission,
    ))
}

fn typed_payload_validity(
    payload: &[u8],
    envelope_epoch: u64,
) -> Result<(u64, u64, u64), AuthorityError> {
    let value: Value = crate::strict_json::parse(payload)?;
    let object = value
        .as_object()
        .ok_or(AuthorityError::InvalidStageEnvelope)?;
    let number = |name| {
        object
            .get(name)
            .and_then(Value::as_u64)
            .ok_or(AuthorityError::InvalidStageEnvelope)
    };
    let valid_from = number("valid_from")?;
    let expires_at = number("expires_at")?;
    let revocation_epoch = number("revocation_epoch")?;
    if valid_from >= expires_at || revocation_epoch == 0 || revocation_epoch != envelope_epoch {
        return Err(AuthorityError::InvalidStageEnvelope);
    }
    Ok((valid_from, expires_at, revocation_epoch))
}

fn envelope_from_bytes(
    bytes: &[u8],
) -> Result<(StageAuthorityEnvelopeV1, [u8; 64]), AuthorityError> {
    let mut value = crate::strict_json::parse(bytes)?;
    let object = value
        .as_object_mut()
        .ok_or(AuthorityError::InvalidStageEnvelope)?;
    let signature = signature(object.remove("signature"))?;
    for name in [
        "bootstrap_receipt_sha256",
        "payload_schema_sha256",
        "payload_sha256",
    ] {
        hex_array(object, name)?;
    }
    let envelope = serde_json::from_value::<StageAuthorityEnvelopeV1>(value)
        .map_err(|_| AuthorityError::InvalidStageEnvelope)?;
    if canonical_checked_in_stage_envelope(&envelope, &signature)? != bytes {
        return Err(AuthorityError::InvalidCanonicalReceipt);
    }
    Ok((envelope, signature))
}
