use gocode_promotion_contracts::{ContractError, validate_rc3_v2_graph, validate_rc3_v2_payload};

const MANIFEST: &str = "gocode.release.publication-manifest/2";

fn canonical_manifest() -> Vec<u8> {
    let value: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/rc3_v2_corpus.json")).unwrap();
    serde_json::to_vec(&value["publication_manifest"]).unwrap()
}

fn payload(name: &str) -> Vec<u8> {
    let value: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/rc3_v2_corpus.json")).unwrap();
    serde_json::to_vec(&value[name]).unwrap()
}

#[test]
fn validates_and_hashes_the_closed_rc3_v2_manifest_without_a_line_feed() {
    let canonical = canonical_manifest();
    let validated = validate_rc3_v2_payload(MANIFEST, &canonical).unwrap();
    assert_eq!(validated.bytes(), canonical);
    assert_ne!(validated.sha256(), [0; 32]);
    assert_eq!(
        validate_rc3_v2_payload(MANIFEST, &[canonical.as_slice(), b"\n"].concat()),
        Err(ContractError::InvalidCanonicalPayload)
    );
}

#[test]
fn rejects_closed_manifest_artifact_and_human_mutations() {
    for name in ["missing", "alias", "order", "checksum", "macos"] {
        let mut value: serde_json::Value =
            serde_json::from_slice(&payload("publication_manifest")).unwrap();
        match name {
            "missing" => {
                value["human_artifacts"]
                    .as_object_mut()
                    .unwrap()
                    .remove("checksums");
            }
            "alias" => {
                value["human_artifacts"]["checksums"] = value["human_artifacts"]["sbom"].clone();
            }
            "order" => value["public_artifacts"].as_array_mut().unwrap().reverse(),
            "checksum" => {
                value["public_artifacts"][0]["checksum_sha256"] =
                    value["public_artifacts"][0]["artifact_sha256"].clone();
            }
            "macos" => value["public_artifacts"][0]["platform"] = serde_json::json!("macos"),
            _ => unreachable!(),
        }
        assert_eq!(
            validate_rc3_v2_payload(MANIFEST, &serde_json::to_vec(&value).unwrap()),
            Err(ContractError::InvalidCanonicalPayload),
            "{name}"
        );
    }
}

#[test]
fn rejects_final_review_and_authorization_identity_policy_mutations() {
    for (schema, corpus, name) in [
        (
            "gocode.release.rc3-final-review/1",
            "final_review",
            "reviewer",
        ),
        (
            "gocode.release.rc3-publication-authorization/2",
            "authorization",
            "self_execution",
        ),
        (
            "gocode.release.rc3-publication-authorization/2",
            "authorization",
            "executor_lane",
        ),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&payload(corpus)).unwrap();
        match name {
            "reviewer" => value["reviewer"]["key_id"] = serde_json::json!("not-a-digest"),
            "self_execution" => value["self_execution"] = serde_json::json!(true),
            "executor_lane" => {
                value["executor"]["lane_id"] = value["authorizer"]["lane_id"].clone();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            validate_rc3_v2_payload(schema, &serde_json::to_vec(&value).unwrap()),
            Err(ContractError::InvalidCanonicalPayload),
            "{name}"
        );
    }
}

#[test]
fn validates_a_digest_coherent_rc3_v2_graph_and_rejects_a_mixed_digest() {
    let manifest = validate_rc3_v2_payload(MANIFEST, &payload("publication_manifest")).unwrap();
    let review = validate_rc3_v2_payload(
        "gocode.release.rc3-final-review/1",
        &payload("final_review"),
    )
    .unwrap();
    let authorization = validate_rc3_v2_payload(
        "gocode.release.rc3-publication-authorization/2",
        &payload("authorization"),
    )
    .unwrap();
    assert!(validate_rc3_v2_graph(&manifest, &review, &authorization).is_ok());
    let mut mixed: serde_json::Value = serde_json::from_slice(&payload("authorization")).unwrap();
    mixed["publication_manifest_sha256"] = serde_json::json!("a".repeat(64));
    let mixed = validate_rc3_v2_payload(
        "gocode.release.rc3-publication-authorization/2",
        &serde_json::to_vec(&mixed).unwrap(),
    )
    .unwrap();
    assert_eq!(
        validate_rc3_v2_graph(&manifest, &review, &mixed),
        Err(ContractError::IncoherentRc3V2Graph)
    );
}
