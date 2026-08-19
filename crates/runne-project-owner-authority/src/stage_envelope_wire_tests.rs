//! RC2 and RC3 successful raw transition-envelope vectors.
use crate::{
    AuthorityError, DelegationV1, STAGE_ENVELOPE_SCHEMA_V1, SigningDomain,
    StageAuthorityEnvelopeV1, canonical_checked_in_stage_envelope, canonical_stage_payload,
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
fn rc2_and_legacy_rc3_transition_envelopes_reach_validation_with_exact_pins() {
    for (role, schema_id, seed) in [
        (
            "RC2_SIGNING_AUTHORIZER",
            "runne.release.rc2-signing-authorization/1",
            12_u8,
        ),
        (
            "RC3_PUBLICATION_AUTHORIZER",
            "runne.release.rc3-publication-authorization/1",
            13,
        ),
    ] {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
        let delegation = DelegationV1 {
            role: role.into(),
            principal_id: "principal-2".into(),
            controlling_account_id: "account-2".into(),
            lane_id: "lane-2".into(),
            key_id: crate::receipt_validation::hex(&crate::key_id(&public_key)),
            public_key,
            key_epoch: 1,
            signature_profile_id: "profile-2".into(),
            not_before: "2026-08-13T00:00:00Z".into(),
            expires_at: "2026-08-13T00:00:04Z".into(),
            revocation_epoch: 1,
            allowed_payload_schema_ids: vec![schema_id.into()],
        };
        let payload = serde_json::json!({"schema_version":schema_id});
        let envelope = StageAuthorityEnvelopeV1 {
            schema_version: STAGE_ENVELOPE_SCHEMA_V1.into(),
            repository_id: "runne".into(),
            bootstrap_receipt_sha256: [1; 32],
            issuer_role: role.into(),
            issuer_principal_id: delegation.principal_id.clone(),
            issuer_controlling_account_id: delegation.controlling_account_id.clone(),
            issuer_lane_id: delegation.lane_id.clone(),
            issuer_key_id: delegation.key_id.clone(),
            issuer_key_epoch: 1,
            signature_profile_id: delegation.signature_profile_id.clone(),
            payload_schema_id: schema_id.into(),
            payload_schema_sha256: crate::v3_trust_schema_digests()
                .unwrap()
                .into_iter()
                .find(|pin| pin.schema_id == schema_id)
                .unwrap()
                .schema_sha256,
            payload_sha256: Sha256::digest(canonical_stage_payload(&payload).unwrap()).into(),
            payload,
            issued_at: "2026-08-13T00:00:01Z".into(),
            not_before: "2026-08-13T00:00:02Z".into(),
            expires_at: "2026-08-13T00:00:03Z".into(),
            revocation_epoch: 1,
            authorization_nonce: "nonce-2".into(),
        };
        let domain = crate::SigningDomain::new(STAGE_ENVELOPE_SCHEMA_V1, role, "runne").unwrap();
        let signature = key
            .sign(&signing_transcript(
                &domain,
                &crate::canonical_unsigned_stage_envelope(&envelope).unwrap(),
            ))
            .to_bytes();
        let bytes = canonical_checked_in_stage_envelope(&envelope, &signature).unwrap();
        let outcome = verify_stage_envelope_bytes(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &verified_bootstrap(
                [1; 32],
                vec![delegation],
                [9; 32],
                test_empty_subject(),
                String::new(),
            ),
            &TestContext,
        );
        if schema_id == "runne.release.rc3-publication-authorization/1" {
            assert_eq!(outcome, Err(AuthorityError::AuthorityVersionSuperseded));
        } else {
            assert_eq!(outcome, Err(AuthorityError::InvalidStageEnvelope));
        }
    }
}

#[test]
fn legacy_rc3_publication_authorization_v1_envelope_is_superseded_before_verification() {
    let key = SigningKey::from_bytes(&[14; 32]);
    let schema_id = "runne.release.rc3-publication-authorization/1";
    let delegation = DelegationV1 {
        role: "RC3_PUBLICATION_AUTHORIZER".into(),
        principal_id: "principal-3".into(),
        controlling_account_id: "account-3".into(),
        lane_id: "lane-3".into(),
        key_id: crate::receipt_validation::hex(&crate::key_id(&key.verifying_key().to_bytes())),
        public_key: key.verifying_key().to_bytes(),
        key_epoch: 1,
        signature_profile_id: "profile-3".into(),
        not_before: "2026-08-13T00:00:00Z".into(),
        expires_at: "2026-08-13T00:00:04Z".into(),
        revocation_epoch: 1,
        allowed_payload_schema_ids: vec![schema_id.into()],
    };
    let payload = serde_json::json!({"schema_version":schema_id});
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
        payload_schema_id: schema_id.into(),
        payload_schema_sha256: crate::v3_trust_schema_digests()
            .unwrap()
            .into_iter()
            .find(|pin| pin.schema_id == schema_id)
            .unwrap()
            .schema_sha256,
        payload_sha256: Sha256::digest(canonical_stage_payload(&payload).unwrap()).into(),
        payload,
        issued_at: "2026-08-13T00:00:01Z".into(),
        not_before: "2026-08-13T00:00:02Z".into(),
        expires_at: "2026-08-13T00:00:03Z".into(),
        revocation_epoch: 1,
        authorization_nonce: "nonce-3".into(),
    };
    let domain =
        SigningDomain::new(STAGE_ENVELOPE_SCHEMA_V1, &envelope.issuer_role, "runne").unwrap();
    let signature = key
        .sign(&signing_transcript(
            &domain,
            &crate::canonical_unsigned_stage_envelope(&envelope).unwrap(),
        ))
        .to_bytes();
    let bytes = canonical_checked_in_stage_envelope(&envelope, &signature).unwrap();
    assert_eq!(
        verify_stage_envelope_bytes(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &verified_bootstrap(
                [1; 32],
                vec![delegation],
                [9; 32],
                test_empty_subject(),
                String::new()
            ),
            &TestContext
        ),
        Err(AuthorityError::AuthorityVersionSuperseded)
    );
}

#[test]
fn rejects_schema_version_only_stage_payload() {
    let key = SigningKey::from_bytes(&[29; 32]);
    let delegation = DelegationV1 {
        role: "RC1_QUALIFICATION_AUTHORIZER".into(),
        principal_id: "principal-1".into(),
        controlling_account_id: "account-1".into(),
        lane_id: "lane-1".into(),
        key_id: crate::receipt_validation::hex(&crate::key_id(&key.verifying_key().to_bytes())),
        public_key: key.verifying_key().to_bytes(),
        key_epoch: 1,
        signature_profile_id: "profile-1".into(),
        not_before: "2026-08-13T00:00:00Z".into(),
        expires_at: "2026-08-13T00:00:04Z".into(),
        revocation_epoch: 1,
        allowed_payload_schema_ids: vec!["runne.release.rc1-qualification-decision/1".into()],
    };
    let payload =
        serde_json::json!({"schema_version":"runne.release.rc1-qualification-decision/1"});
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
        authorization_nonce: "nonce-1".into(),
    };
    let domain =
        SigningDomain::new(STAGE_ENVELOPE_SCHEMA_V1, &envelope.issuer_role, "runne").unwrap();
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
}
