//! Raw cryptographic chain through all delegated promotion stages.

use ed25519_dalek::{Signer as _, SigningKey};
use runne_project_owner_authority::{
    AuthorityError, STAGE_ENVELOPE_SCHEMA_V1, SigningDomain, StageAuthorityEnvelopeV1,
    canonical_checked_in_promotion_bootstrap, canonical_checked_in_stage_envelope,
    canonical_stage_payload, signing_transcript, v3_trust_schema_digests,
    verify_promotion_bootstrap_bytes, verify_stage_envelope_bytes,
};
use sha2::{Digest, Sha256};

mod raw_promotion_support;
use raw_promotion_support::{
    BootstrapContext,
    chain::{delegation, signed_bootstrap},
};

struct TestContext;
impl runne_project_owner_authority::StageVerificationContext for TestContext {
    fn admit_or_recover(
        &self,
        _: &runne_project_owner_authority::StageAdmissionRequest<'_>,
    ) -> Result<
        runne_project_owner_authority::StageAdmission,
        runne_project_owner_authority::AuthorityError,
    > {
        Ok(runne_project_owner_authority::StageAdmission::NewlyAdmitted)
    }
}

#[test]
fn raw_chain_verifies_v2_to_v3_bootstrap_and_all_stage_envelopes() {
    let (_, trust, predecessor, signed) = signed_bootstrap();
    let bytes =
        canonical_checked_in_promotion_bootstrap(&signed.unsigned, &signed.signature).unwrap();
    let verified = verify_promotion_bootstrap_bytes(
        &bytes,
        signed.project_owner_authority_receipt_sha256,
        &trust,
        &predecessor,
        &BootstrapContext::valid(),
    )
    .unwrap();
    assert_eq!(verified.root_identity().principal_id(), "root-principal");
    let keys = [
        SigningKey::from_bytes(&[50; 32]),
        SigningKey::from_bytes(&[51; 32]),
        SigningKey::from_bytes(&[52; 32]),
    ];
    for ((role, schema_id), key) in [
        (
            "RC1_QUALIFICATION_AUTHORIZER",
            "runne.release.rc1-qualification-decision/1",
        ),
        (
            "RC2_SIGNING_AUTHORIZER",
            "runne.release.rc2-signing-authorization/1",
        ),
        (
            "RC3_PUBLICATION_AUTHORIZER",
            "runne.release.rc3-publication-authorization/1",
        ),
    ]
    .into_iter()
    .zip(keys)
    {
        let payload = stage_payload(schema_id);
        let delegation = delegation(role, &key);
        let envelope = StageAuthorityEnvelopeV1 {
            schema_version: STAGE_ENVELOPE_SCHEMA_V1.into(),
            repository_id: "runne".into(),
            bootstrap_receipt_sha256: verified.receipt_sha256(),
            issuer_role: role.into(),
            issuer_principal_id: delegation.principal_id,
            issuer_controlling_account_id: delegation.controlling_account_id,
            issuer_lane_id: delegation.lane_id,
            issuer_key_id: delegation.key_id,
            issuer_key_epoch: 1,
            signature_profile_id: delegation.signature_profile_id,
            payload_schema_id: schema_id.into(),
            payload_schema_sha256: v3_trust_schema_digests()
                .unwrap()
                .into_iter()
                .find(|pin| pin.schema_id == schema_id)
                .unwrap()
                .schema_sha256,
            payload_sha256: Sha256::digest(canonical_stage_payload(&payload).unwrap()).into(),
            payload,
            issued_at: "2026-08-13T00:00:02Z".into(),
            not_before: "2026-08-13T00:00:03Z".into(),
            expires_at: "2026-08-13T00:00:04Z".into(),
            revocation_epoch: 1,
            authorization_nonce: format!("nonce-{}", &role[2..3]),
        };
        let domain = SigningDomain::new(STAGE_ENVELOPE_SCHEMA_V1, role, "runne").unwrap();
        let signature = key
            .sign(&signing_transcript(
                &domain,
                &runne_project_owner_authority::canonical_unsigned_stage_envelope(&envelope)
                    .unwrap(),
            ))
            .to_bytes();
        let bytes = canonical_checked_in_stage_envelope(&envelope, &signature).unwrap();
        let envelope_digest: [u8; 32] = Sha256::digest(&bytes[..bytes.len() - 1]).into();
        let outcome = verify_stage_envelope_bytes(&bytes, envelope_digest, &verified, &TestContext);
        if schema_id == "runne.release.rc3-publication-authorization/1" {
            assert_eq!(outcome, Err(AuthorityError::AuthorityVersionSuperseded));
        } else {
            assert!(outcome.is_ok());
        }
    }
}

fn stage_payload(schema_id: &str) -> serde_json::Value {
    let digest = "a".repeat(64);
    match schema_id {
        "runne.release.rc1-qualification-decision/1" => serde_json::json!({
            "schema_version":schema_id,"candidate_binding_sha256":digest,"subject_sha256":"b".repeat(64),"matrix_sha256":"c".repeat(64),"bootstrap_sha256":"d".repeat(64),"candidate_sha256":"e".repeat(64),"policy_sha256":"f".repeat(64),"release_facts_sha256":"1".repeat(64),
            "approver":{"principal_id":"a","account_id":"b","lane_id":"c","key_id":"d","signature_profile_id":"e"},"valid_from":1,"expires_at":2,"revocation_epoch":1,"disposition":"qualified_unsigned","signing_allowed":false,"publication_allowed":false,"external_effects":[]
        }),
        "runne.release.rc2-signing-authorization/1" => {
            serde_json::json!({
                "schema_version":schema_id,"parent_candidate_sha256":digest,
                "unsigned_manifest_sha256":"b".repeat(64),
                "pre_sign_artifacts":[
                    {"artifact_slot_id":"linux-appimage","platform":"linux","operation":"native_sign","expected_artifact_sha256":"c".repeat(64),"expected_artifact_length":1},
                    {"artifact_slot_id":"linux-deb","platform":"linux","operation":"native_sign","expected_artifact_sha256":"d".repeat(64),"expected_artifact_length":2},
                    {"artifact_slot_id":"windows-installer-unsigned","platform":"windows","operation":"native_sign","expected_artifact_sha256":"2".repeat(64),"expected_artifact_length":3}
                ],
                "signer":identity("signer"),"runner":identity("runner"),"reviewer":identity("reviewer"),"update_issuer":identity("issuer"),
                "workflow_sha256":"e".repeat(64),"effect_namespace":"effects","effect_generation":1,"valid_from":1,"expires_at":2,"revocation_epoch":1
            })
        }
        _ => {
            serde_json::json!({"schema_version":schema_id,"inventory_sha256":digest,"report_sha256":"b".repeat(64),"publication_manifest_sha256":"c".repeat(64),"executor_principal":"executor","lane":"lane","workflow_sha256":"d".repeat(64),"idempotency_namespace":"namespace","destination":"repo:path","channel":"stable","valid_from":1,"expires_at":2,"revocation_epoch":1,"no_effect":true,"external_effects":[]})
        }
    }
}

fn identity(name: &str) -> serde_json::Value {
    serde_json::json!({
        "principal_id":format!("{name}-principal"),"account_id":format!("{name}-account"),
        "lane_id":format!("{name}-lane"),"key_id":format!("{name}-key"),
        "signature_profile_id":format!("{name}-profile")
    })
}
