//! Recovery regression tests for durable stage-envelope admission.

use std::cell::{Cell, RefCell};

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::{
    AuthorityError, DelegationV1, STAGE_ENVELOPE_SCHEMA_V1, SigningDomain,
    StageAuthorityEnvelopeV1, canonical_checked_in_stage_envelope, canonical_stage_payload,
    receipt_v4::{test_empty_subject, verified_bootstrap},
    signing_transcript,
    stage_envelope_wire::verify_stage_envelope_bytes,
};

struct RecoveringContext {
    time: Cell<u8>,
    claimed: RefCell<Option<[u8; 32]>>,
}
impl RecoveringContext {
    const fn new() -> Self {
        Self {
            time: Cell::new(0),
            claimed: RefCell::new(None),
        }
    }
}
impl crate::StageVerificationContext for RecoveringContext {
    fn admit_or_recover(
        &self,
        request: &crate::StageAdmissionRequest<'_>,
    ) -> Result<crate::StageAdmission, AuthorityError> {
        let mut claimed = self.claimed.borrow_mut();
        if let Some(previous) = *claimed {
            return (previous == request.scope.envelope_sha256)
                .then_some(crate::StageAdmission::ExistingSame)
                .ok_or(AuthorityError::ReplayedStageEnvelope);
        }
        (self.time.get() == 0)
            .then(|| {
                *claimed = Some(request.scope.envelope_sha256);
                crate::StageAdmission::NewlyAdmitted
            })
            .ok_or(AuthorityError::StaleOrRevokedStageEnvelope)
    }
}

#[test]
fn durable_exact_claim_recovers_after_envelope_expiry() {
    let (bytes, bootstrap) = signed_rc1_envelope();
    let context = RecoveringContext::new();
    let digest = Sha256::digest(&bytes[..bytes.len() - 1]).into();
    assert!(verify_stage_envelope_bytes(&bytes, digest, &bootstrap, &context).is_ok());
    context.time.set(1);
    assert!(verify_stage_envelope_bytes(&bytes, digest, &bootstrap, &context).is_ok());
}

#[test]
fn invalid_neutral_payload_never_calls_stage_context() {
    let (bytes, bootstrap) = signed_rc1_envelope();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("signature");
    for name in [
        "bootstrap_receipt_sha256",
        "payload_schema_sha256",
        "payload_sha256",
    ] {
        object.insert(name.into(), hex_array(object[name].as_str().unwrap()));
    }
    object["payload"]["approver"]["principal_id"] = serde_json::json!("Uppercase");
    let mut envelope: StageAuthorityEnvelopeV1 = serde_json::from_value(value).unwrap();
    envelope.payload_sha256 =
        Sha256::digest(canonical_stage_payload(&envelope.payload).unwrap()).into();
    let signature = SigningKey::from_bytes(&[42; 32])
        .sign(&signing_transcript(
            &SigningDomain::new(STAGE_ENVELOPE_SCHEMA_V1, &envelope.issuer_role, "runne").unwrap(),
            &crate::canonical_unsigned_stage_envelope(&envelope).unwrap(),
        ))
        .to_bytes();
    let bytes = canonical_checked_in_stage_envelope(&envelope, &signature).unwrap();
    let context = CountingContext(Cell::new(0));
    assert_eq!(
        verify_stage_envelope_bytes(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &bootstrap,
            &context,
        ),
        Err(AuthorityError::InvalidStageEnvelope)
    );
    assert_eq!(context.0.get(), 0);
}

fn hex_array(value: &str) -> serde_json::Value {
    serde_json::Value::Array(
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                serde_json::Value::from(
                    u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap(),
                )
            })
            .collect(),
    )
}

struct CountingContext(Cell<u8>);
impl crate::StageVerificationContext for CountingContext {
    fn admit_or_recover(
        &self,
        _: &crate::StageAdmissionRequest<'_>,
    ) -> Result<crate::StageAdmission, AuthorityError> {
        self.0.set(self.0.get() + 1);
        Ok(crate::StageAdmission::NewlyAdmitted)
    }
}

fn signed_rc1_envelope() -> (Vec<u8>, crate::VerifiedPromotionBootstrap) {
    let key = SigningKey::from_bytes(&[42; 32]);
    let public_key = key.verifying_key().to_bytes();
    let delegation = DelegationV1 {
        role: "RC1_QUALIFICATION_AUTHORIZER".into(),
        principal_id: "principal".into(),
        controlling_account_id: "account".into(),
        lane_id: "lane".into(),
        key_id: crate::receipt_validation::hex(&crate::key_id(&public_key)),
        public_key,
        key_epoch: 1,
        signature_profile_id: "profile".into(),
        not_before: "2026-08-13T00:00:00Z".into(),
        expires_at: "2026-08-13T00:00:04Z".into(),
        revocation_epoch: 1,
        allowed_payload_schema_ids: vec!["runne.release.rc1-qualification-decision/1".into()],
    };
    let payload = serde_json::json!({"schema_version":"runne.release.rc1-qualification-decision/1","candidate_binding_sha256":"a".repeat(64),"subject_sha256":"b".repeat(64),"matrix_sha256":"c".repeat(64),"bootstrap_sha256":"d".repeat(64),"candidate_sha256":"e".repeat(64),"policy_sha256":"f".repeat(64),"release_facts_sha256":"1".repeat(64),"approver":{"principal_id":"p","account_id":"a","lane_id":"l","key_id":"k","signature_profile_id":"q"},"valid_from":1,"expires_at":2,"revocation_epoch":1,"disposition":"qualified_unsigned","signing_allowed":false,"publication_allowed":false,"external_effects":[]});
    let envelope = StageAuthorityEnvelopeV1 {
        schema_version: STAGE_ENVELOPE_SCHEMA_V1.into(),
        repository_id: "runne".into(),
        bootstrap_receipt_sha256: [1; 32],
        issuer_role: delegation.role.clone(),
        issuer_principal_id: delegation.principal_id.clone(),
        issuer_controlling_account_id: delegation.controlling_account_id.clone(),
        issuer_lane_id: delegation.lane_id.clone(),
        issuer_key_id: delegation.key_id.clone(),
        issuer_key_epoch: 1,
        signature_profile_id: delegation.signature_profile_id.clone(),
        payload_schema_id: delegation.allowed_payload_schema_ids[0].clone(),
        payload_schema_sha256: crate::v3_trust_schema_digests()
            .unwrap()
            .into_iter()
            .find(|pin| pin.schema_id == "runne.release.rc1-qualification-decision/1")
            .unwrap()
            .schema_sha256,
        payload_sha256: Sha256::digest(canonical_stage_payload(&payload).unwrap()).into(),
        payload,
        issued_at: "2026-08-13T00:00:01Z".into(),
        not_before: "2026-08-13T00:00:02Z".into(),
        expires_at: "2026-08-13T00:00:03Z".into(),
        revocation_epoch: 1,
        authorization_nonce: "nonce".into(),
    };
    let signature = key
        .sign(&signing_transcript(
            &SigningDomain::new(STAGE_ENVELOPE_SCHEMA_V1, &envelope.issuer_role, "runne").unwrap(),
            &crate::canonical_unsigned_stage_envelope(&envelope).unwrap(),
        ))
        .to_bytes();
    (
        canonical_checked_in_stage_envelope(&envelope, &signature).unwrap(),
        verified_bootstrap(
            [1; 32],
            vec![delegation],
            [9; 32],
            test_empty_subject(),
            String::new(),
        ),
    )
}
