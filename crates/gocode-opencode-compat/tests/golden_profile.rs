#![allow(unused_imports)]
//! L1 golden tests — artifact generation, byte-identical regeneration,
//! schema validation, positive + negative fixtures.
use std::fs;

use gocode_opencode_compat::inventory::{INVENTORY, classify};
use gocode_opencode_compat::profile::{
    OperationSelector, ProfileId, TranslationDecision, Transport,
};
use gocode_opencode_compat::translate::translate_request;

mod support;
use support::serialize;

const PROFILE_ID: &str = "opencode-baseline-inventory";
const ARTIFACT_PATH: &str = "../../docs/profiles/opencode-baseline-inventory-v1.json";
const DIGEST_PATH: &str = "../../docs/profiles/opencode-baseline-inventory-v1.digest";
const SCHEMA_PATH: &str = "../../docs/schemas/opencode-baseline-inventory-v1.schema.json";
const V2_ARTIFACT_PATH: &str = "../../docs/profiles/opencode-baseline-inventory-v2.json";
const V2_DIGEST_PATH: &str = "../../docs/profiles/opencode-baseline-inventory-v2.digest";
const V2_SCHEMA_PATH: &str = "../../docs/schemas/opencode-baseline-inventory-v2.schema.json";
const V3_ARTIFACT_PATH: &str = "../../docs/profiles/opencode-baseline-inventory-v3.json";
const V3_DIGEST_PATH: &str = "../../docs/profiles/opencode-baseline-inventory-v3.digest";
const V3_SCHEMA_PATH: &str = "../../docs/schemas/opencode-baseline-inventory-v3.schema.json";

#[test]
fn test_inventory_completeness() {
    // All 5 baseline routes must be present
    let routes = vec![
        ("POST", "/session"),
        ("POST", "/session/:sessionID/message"),
        ("POST", "/session/:sessionID/prompt_async"),
        ("GET", "/session/status"),
        ("POST", "/session/:sessionID/abort"),
    ];
    for (method, path) in routes {
        let sel = OperationSelector {
            transport: Transport::HTTP,
            method: method.into(),
            normalized_path: path.into(),
        };
        assert!(
            classify(&sel).is_some(),
            "missing route: {} {}",
            method,
            path
        );
    }
}

#[test]
fn profile_revisions_expose_only_their_verified_routes() {
    let pid = ProfileId::new(PROFILE_ID).expect("profile");
    for revision in [1, 2, 3] {
        for entry in INVENTORY.iter() {
            let accepted = matches!(
                translate_request(&pid, revision, entry.selector.clone()),
                TranslationDecision::Accept(_)
            );
            let expected = match revision {
                1 => false,
                2 => entry.inventory_id == "session.create",
                3 => true,
                _ => unreachable!(),
            };
            assert_eq!(
                accepted, expected,
                "unexpected disposition for revision {revision} and {}",
                entry.inventory_id
            );
        }
    }
}

#[test]
fn test_unknown_operation() {
    let pid = ProfileId::new(PROFILE_ID).expect("profile");
    let sel = OperationSelector {
        transport: Transport::HTTP,
        method: "POST".into(),
        normalized_path: "/nonexistent".into(),
    };
    let decision = translate_request(&pid, 1, sel);
    match decision {
        TranslationDecision::Reject(rej) => {
            assert!(matches!(
                rej.code,
                gocode_opencode_compat::classify::RejectionCode::UnknownOperation
            ));
        }
        TranslationDecision::Accept(_) => panic!("unknown operation must fail closed"),
    }
}

#[test]
fn unknown_profile_revision_fails_closed() {
    let pid = ProfileId::new(PROFILE_ID).expect("profile");
    let decision = translate_request(&pid, 4, INVENTORY[0].selector.clone());
    match decision {
        TranslationDecision::Reject(rej) => assert!(matches!(
            rej.code,
            gocode_opencode_compat::classify::RejectionCode::ProfileMismatch
        )),
        TranslationDecision::Accept(_) => panic!("unknown revision must fail closed"),
    }
}

#[test]
fn test_generate_and_verify_artifact() {
    let generated = serialize::canonicalize_inventory();
    let generated_digest = serialize::compute_digest(&generated);
    let committed = fs::read(ARTIFACT_PATH).unwrap();
    let committed_digest = fs::read_to_string(DIGEST_PATH).unwrap();

    // Verify artifact is valid JSON
    let _: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    assert_eq!(committed, generated, "committed V1 artifact is stale");
    assert_eq!(
        committed_digest, generated_digest,
        "committed V1 digest is stale"
    );

    // Verify schema exists and is valid JSON
    let schema_bytes = fs::read(SCHEMA_PATH).unwrap();
    let schema: serde_json::Value = serde_json::from_slice(&schema_bytes).unwrap();
    assert!(schema.is_object(), "schema must be a JSON object");
}

#[test]
fn profile_v2_is_canonical_schema_valid_and_has_exact_digests() {
    use sha2::{Digest, Sha256};

    let generated = serialize::canonicalize_profile_v2();
    let generated_digest = serialize::compute_digest(&generated);
    let committed = fs::read(V2_ARTIFACT_PATH).unwrap();
    let committed_digest = fs::read_to_string(V2_DIGEST_PATH).unwrap();
    assert_eq!(committed, generated, "committed V2 artifact is stale");
    assert_eq!(
        committed_digest, generated_digest,
        "committed V2 digest is stale"
    );
    let artifact: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    let schema_bytes = fs::read(V2_SCHEMA_PATH).unwrap();
    let schema_value: serde_json::Value = serde_json::from_slice(&schema_bytes).unwrap();
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema_value)
        .unwrap();
    assert!(schema.is_valid(&artifact));
    assert_eq!(
        artifact["digests"]["profile_schema_digest"],
        format!("sha256:{:x}", Sha256::digest(&schema_bytes))
    );
    assert_eq!(
        artifact["digests"]["inventory_digest"],
        format!(
            "sha256:{:x}",
            Sha256::digest(serde_jcs::to_vec(&artifact["inventory"]).unwrap())
        )
    );
    let session_create = artifact["inventory"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["inventory_id"] == "session.create")
        .unwrap();
    assert_eq!(session_create["classification"], "Semantic");
    assert_eq!(session_create["status"], "Verified");
}

#[test]
fn profile_v3_is_canonical_schema_valid_and_verifies_all_five_routes() {
    use sha2::{Digest, Sha256};

    let generated = serialize::canonicalize_profile_v3();
    let committed = fs::read(V3_ARTIFACT_PATH).unwrap();
    assert_eq!(committed, generated, "committed V3 artifact is stale");
    assert_eq!(
        fs::read_to_string(V3_DIGEST_PATH).unwrap(),
        serialize::compute_digest(&generated)
    );
    let artifact: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    let schema_bytes = fs::read(V3_SCHEMA_PATH).unwrap();
    let schema_value: serde_json::Value = serde_json::from_slice(&schema_bytes).unwrap();
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema_value)
        .unwrap();
    assert!(schema.is_valid(&artifact));
    assert_eq!(
        artifact["digests"]["profile_schema_digest"],
        format!("sha256:{:x}", Sha256::digest(&schema_bytes))
    );
    assert_eq!(
        artifact["inventory"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["status"] == "Verified")
            .count(),
        5
    );
}

#[test]
#[ignore = "explicit profile regeneration command"]
fn regenerate_profile_artifacts() {
    let v1 = serialize::canonicalize_inventory();
    fs::write(ARTIFACT_PATH, &v1).unwrap();
    fs::write(DIGEST_PATH, serialize::compute_digest(&v1)).unwrap();

    let v2 = serialize::canonicalize_profile_v2();
    fs::write(V2_ARTIFACT_PATH, &v2).unwrap();
    fs::write(V2_DIGEST_PATH, serialize::compute_digest(&v2)).unwrap();

    let v3 = serialize::canonicalize_profile_v3();
    fs::write(V3_ARTIFACT_PATH, &v3).unwrap();
    fs::write(V3_DIGEST_PATH, serialize::compute_digest(&v3)).unwrap();
}
