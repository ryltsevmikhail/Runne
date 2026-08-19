use runne_promotion_contracts::{ContractError, validate_stage_payload};

const SCHEMA: &str = "runne.release.rc1-qualification-decision/1";

fn canonical() -> Vec<u8> {
    br#"{"approver":{"account_id":"account","key_id":"key","lane_id":"lane","principal_id":"principal","signature_profile_id":"profile"},"bootstrap_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","candidate_binding_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","candidate_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","disposition":"qualified_unsigned","expires_at":2,"external_effects":[],"matrix_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","policy_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","publication_allowed":false,"release_facts_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","revocation_epoch":1,"schema_version":"runne.release.rc1-qualification-decision/1","signing_allowed":false,"subject_sha256":"ffffffffffffffffffffffffffffffffaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","valid_from":1}"#.to_vec()
}

#[test]
fn accepts_only_exact_sorted_compact_lf_excluded_bytes() {
    let canonical = canonical();
    assert!(validate_stage_payload(SCHEMA, &canonical).is_ok());
    for changed in [
        [b" ".as_slice(), canonical.as_slice()].concat(),
        [canonical.as_slice(), b"\n"].concat(),
        String::from_utf8(canonical.clone())
            .unwrap()
            .replacen("\"approver\"", "\"z_approver\"", 1)
            .into_bytes(),
    ] {
        assert_eq!(
            validate_stage_payload(SCHEMA, &changed),
            Err(ContractError::InvalidCanonicalPayload)
        );
    }
}

#[test]
fn rejects_identifiers_outside_the_pinned_schema_pattern() {
    let corpus: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/stage_identifier_corpus.json")).unwrap();
    for identifier in corpus["invalid_ids"].as_array().unwrap() {
        let identifier = identifier.as_str().unwrap();
        let invalid = String::from_utf8(canonical())
            .expect("fixture UTF-8")
            .replacen("\"principal\"", &format!("\"{identifier}\""), 1);
        assert_eq!(
            validate_stage_payload(SCHEMA, invalid.as_bytes()),
            Err(ContractError::InvalidCanonicalPayload),
            "{identifier:?}"
        );
    }
    let oversized = "a".repeat(129);
    let invalid = String::from_utf8(canonical())
        .expect("fixture UTF-8")
        .replacen("\"principal\"", &format!("\"{oversized}\""), 1);
    assert_eq!(
        validate_stage_payload(SCHEMA, invalid.as_bytes()),
        Err(ContractError::InvalidCanonicalPayload)
    );
    for epoch in corpus["invalid_revocation_epochs"].as_array().unwrap() {
        let invalid = String::from_utf8(canonical())
            .expect("fixture UTF-8")
            .replacen(
                "\"revocation_epoch\":1",
                &format!("\"revocation_epoch\":{epoch}"),
                1,
            );
        assert_eq!(
            validate_stage_payload(SCHEMA, invalid.as_bytes()),
            Err(ContractError::InvalidCanonicalPayload)
        );
    }
}

#[test]
fn accepts_only_the_explicit_current_production_pre_sign_slots() {
    let value = rc2_canonical();
    assert!(validate_stage_payload("runne.release.rc2-signing-authorization/1", &value,).is_ok());
    let macos_preview = String::from_utf8(value).unwrap().replacen(
        "linux-appimage",
        "macos-app-development-adhoc",
        1,
    );
    assert_eq!(
        validate_stage_payload(
            "runne.release.rc2-signing-authorization/1",
            macos_preview.as_bytes(),
        ),
        Err(ContractError::InvalidCanonicalPayload)
    );
}

fn rc2_canonical() -> Vec<u8> {
    const D: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    format!(
        "{{\"effect_generation\":1,\"effect_namespace\":\"namespace\",\"expires_at\":2,\"parent_candidate_sha256\":\"{D}\",\"pre_sign_artifacts\":[{{\"artifact_slot_id\":\"linux-appimage\",\"expected_artifact_length\":1,\"expected_artifact_sha256\":\"{D}\",\"operation\":\"native_sign\",\"platform\":\"linux\"}},{{\"artifact_slot_id\":\"linux-deb\",\"expected_artifact_length\":2,\"expected_artifact_sha256\":\"{D}\",\"operation\":\"native_sign\",\"platform\":\"linux\"}},{{\"artifact_slot_id\":\"windows-installer-unsigned\",\"expected_artifact_length\":5,\"expected_artifact_sha256\":\"{D}\",\"operation\":\"native_sign\",\"platform\":\"windows\"}}],\"reviewer\":{{\"account_id\":\"reviewer-account\",\"key_id\":\"reviewer-key\",\"lane_id\":\"reviewer-lane\",\"principal_id\":\"reviewer-principal\",\"signature_profile_id\":\"reviewer-profile\"}},\"revocation_epoch\":1,\"runner\":{{\"account_id\":\"runner-account\",\"key_id\":\"runner-key\",\"lane_id\":\"runner-lane\",\"principal_id\":\"runner-principal\",\"signature_profile_id\":\"runner-profile\"}},\"schema_version\":\"runne.release.rc2-signing-authorization/1\",\"signer\":{{\"account_id\":\"signer-account\",\"key_id\":\"signer-key\",\"lane_id\":\"signer-lane\",\"principal_id\":\"signer-principal\",\"signature_profile_id\":\"signer-profile\"}},\"unsigned_manifest_sha256\":\"{D}\",\"update_issuer\":{{\"account_id\":\"issuer-account\",\"key_id\":\"issuer-key\",\"lane_id\":\"issuer-lane\",\"principal_id\":\"issuer-principal\",\"signature_profile_id\":\"issuer-profile\"}},\"valid_from\":1,\"workflow_sha256\":\"{D}\"}}"
    ).into_bytes()
}
