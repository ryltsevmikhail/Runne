use crate::{
    AuthorityError, DelegationV1, STAGE_ENVELOPE_SCHEMA_V1, StageAuthorityEnvelopeV1,
    canonical_checked_in_stage_envelope, canonical_stage_payload,
    receipt_v4::{test_empty_subject, verified_bootstrap},
    signing_transcript,
    stage_envelope_wire::verify_stage_envelope_bytes,
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

struct TestContext;
impl crate::StageVerificationContext for TestContext {
    fn admit_or_recover(
        &self,
        _: &crate::StageAdmissionRequest<'_>,
    ) -> Result<crate::StageAdmission, AuthorityError> {
        Ok(crate::StageAdmission::NewlyAdmitted)
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end adversarial raw envelope boundary vector"
)]
fn raw_transition_envelope_reaches_pin_gate_after_real_ed25519_verification() {
    let key = SigningKey::from_bytes(&[11; 32]);
    let public_key = key.verifying_key().to_bytes();
    let delegation = DelegationV1 {
        role: "RC1_QUALIFICATION_AUTHORIZER".into(),
        principal_id: "principal-1".into(),
        controlling_account_id: "account-1".into(),
        lane_id: "lane-1".into(),
        key_id: crate::receipt_validation::hex(&crate::key_id(&public_key)),
        public_key,
        key_epoch: 1,
        signature_profile_id: "profile-1".into(),
        not_before: "2026-08-13T00:00:00Z".into(),
        expires_at: "2026-08-13T00:00:04Z".into(),
        revocation_epoch: 1,
        allowed_payload_schema_ids: vec!["gocode.release.rc1-qualification-decision/1".into()],
    };
    let payload =
        serde_json::json!({"schema_version":"gocode.release.rc1-qualification-decision/1"});
    let envelope = StageAuthorityEnvelopeV1 {
        schema_version: STAGE_ENVELOPE_SCHEMA_V1.into(),
        repository_id: "gocode".into(),
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
            .find(|pin| pin.schema_id == "gocode.release.rc1-qualification-decision/1")
            .unwrap()
            .schema_sha256,
        payload_sha256: Sha256::digest(canonical_stage_payload(&payload).unwrap()).into(),
        payload,
        issued_at: "2026-08-13T00:00:01Z".into(),
        not_before: "2026-08-13T00:00:02Z".into(),
        expires_at: "2026-08-13T00:00:03Z".into(),
        revocation_epoch: 1,
        authorization_nonce: "nonce-1".into(),
    };
    let domain =
        crate::SigningDomain::new(STAGE_ENVELOPE_SCHEMA_V1, &envelope.issuer_role, "gocode")
            .unwrap();
    let signature = key
        .sign(&signing_transcript(
            &domain,
            &crate::canonical_unsigned_stage_envelope(&envelope).unwrap(),
        ))
        .to_bytes();
    let bytes = canonical_checked_in_stage_envelope(&envelope, &signature).unwrap();
    let bootstrap = verified_bootstrap(
        [1; 32],
        vec![delegation],
        [9; 32],
        test_empty_subject(),
        String::new(),
    );
    assert_eq!(
        verify_stage_envelope_bytes(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &bootstrap,
            &TestContext
        ),
        Err(AuthorityError::InvalidStageEnvelope)
    );
    let crlf = String::from_utf8(bytes)
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    assert_eq!(
        verify_stage_envelope_bytes(
            &crlf,
            Sha256::digest(&crlf[..crlf.len() - 2]).into(),
            &bootstrap,
            &TestContext
        ),
        Err(AuthorityError::InvalidCanonicalReceipt)
    );
    let mut malformed: serde_json::Value = serde_json::from_slice(
        &canonical_checked_in_stage_envelope(&envelope, &signature).unwrap(),
    )
    .unwrap();
    malformed["signature"] = serde_json::Value::String("A".into());
    let mut malformed = serde_json::to_vec(&malformed).unwrap();
    malformed.push(b'\n');
    assert_eq!(
        verify_stage_envelope_bytes(
            &malformed,
            Sha256::digest(&malformed[..malformed.len() - 1]).into(),
            &bootstrap,
            &TestContext
        ),
        Err(AuthorityError::InvalidReceiptSignature)
    );
    let mutations: [fn(&mut StageAuthorityEnvelopeV1); 11] = [
        |item| item.bootstrap_receipt_sha256 = [0; 32],
        |item| item.issuer_principal_id = "other".into(),
        |item| item.issuer_controlling_account_id = "other".into(),
        |item| item.issuer_lane_id = "other".into(),
        |item| item.issuer_key_epoch = 2,
        |item| item.signature_profile_id = "other".into(),
        |item| item.revocation_epoch = 2,
        |item| item.payload_schema_id = "gocode.release.rc2-signing-authorization/1".into(),
        |item| item.authorization_nonce = "unsafe/slash".into(),
        |item| item.expires_at = item.not_before.clone(),
        |item| item.payload = serde_json::json!({"nested":{"envelope_sha256":"x"}}),
    ];
    for mutate in mutations {
        let mut changed = envelope.clone();
        mutate(&mut changed);
        let bytes = canonical_checked_in_stage_envelope(&changed, &signature).unwrap();
        assert_eq!(
            verify_stage_envelope_bytes(
                &bytes,
                Sha256::digest(&bytes[..bytes.len() - 1]).into(),
                &bootstrap,
                &TestContext
            ),
            Err(AuthorityError::InvalidStageEnvelope)
        );
    }
}
