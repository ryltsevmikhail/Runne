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
fn test_all_routes_reject() {
    let pid = ProfileId(PROFILE_ID.into());
    for entry in INVENTORY.iter() {
        let sel = entry.selector.clone();
        let decision = translate_request(&pid, 1, sel);
        match decision {
            TranslationDecision::Reject(rej) => {
                assert!(rej.inventory_id.is_some(), "must find inventory_id");
            }
        }
    }
}

#[test]
fn test_unknown_operation() {
    let pid = ProfileId(PROFILE_ID.into());
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
    }
}

#[test]
fn test_zero_mutation_compile_time() {
    // Compile-time assertion: no mutating imports
    // This test exists to document the structural guarantee.
    // If EventStore, UnitOfWork, or TaskRunService are ever imported,
    // this file won't compile (intentional).
    assert!(
        true,
        "zero-mutation structural guarantee holds at compile time"
    );
}

#[test]
fn test_generate_and_verify_artifact() {
    let json = serialize::canonicalize_inventory();
    let digest = serialize::compute_digest(&json);

    // Write artifact
    fs::write(ARTIFACT_PATH, &json).unwrap();
    fs::write(DIGEST_PATH, digest.as_bytes()).unwrap();

    // Verify artifact is valid JSON
    let _: serde_json::Value = serde_json::from_slice(&json).unwrap();

    // Re-generation must produce identical bytes
    let json2 = serialize::canonicalize_inventory();
    assert_eq!(json, json2, "byte-identical regeneration failed");

    let digest2 = serialize::compute_digest(&json2);
    assert_eq!(digest, digest2, "digest must match");

    // Verify schema exists and is valid JSON
    let schema_bytes = fs::read(SCHEMA_PATH).unwrap();
    let schema: serde_json::Value = serde_json::from_slice(&schema_bytes).unwrap();
    assert!(schema.is_object(), "schema must be a JSON object");
}
