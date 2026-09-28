//! NM-10 frozen canary rules shared by every sink-scan target (gateway
//! wiring, provider dispatch/terminal sinks, daemon outbound sinks): the
//! frozen fake canaries (`docs/golden/t1/` fixtures) compiled into
//! `SecretScanner` pattern sets under the frozen SCAN-PLAIN / SCAN-BASE64-STD
//! / SCAN-MARKER rules.
//!
//! Sink boundary: authorized direct file reads of an admitted trusted
//! workspace are §B ingestion/delivery, not §C-E sinks. The secret family
//! (frozen-deny secret values, their base64 forms, the RUNNE_T1_FAKE marker,
//! and the content canaries with absolute "never in any sink" expectations)
//! must be absent from every sink; project-content markers planted in
//! readable file-channel files double as the positive control proving the
//! scans are live.

#[path = "../support/secret_scan.rs"]
pub(super) mod secret_scan;

use std::io::Cursor;

use base64::Engine as _;
use secret_scan::{RepresentationClass, SecretRepresentation};

pub(super) use secret_scan::SecretScanner;

/// Synthetic canary marker only (never a real secret); single source shared
/// by every NM-10 harness target.
pub(super) const CANARY: &str = "RUNNE_T1_FAKE_CANARY_zq71";

pub(super) const FAKE_SECRET_API_KEY: &str = "RUNNE_T1_FAKE_API_KEY_7f3a9c41d2e8b605";
pub(super) const FAKE_SECRET_BEARER: &str = "RUNNE_T1_FAKE_BEARER_b8e2f6a04c19d735ab";
pub(super) const FAKE_SECRET_ENV: &str = "RUNNE_T1_FAKE_ENV_VALUE_3c5d9e1a";
pub(super) const FAKE_SECRET_HEADER: &str =
    "RUNNE_T1_FAKE_HEADER.eyJRUNNE_VDEiOiJGQUtFIn0.RUNNE_T1_FAKE_SIG";
pub(super) const FAKE_SECRET_BLOB: &str = "UlVOTkVfVDFfRkFLRV9CTE9CXzRhYmM4ZWY5";
pub(super) const FAKE_SECRET_CRASH: &str = "RUNNE_T1_FAKE_CRASH_d901be37";
pub(super) const FAKE_SECRET_PEM: &str = "-----BEGIN RUNNE T1 FAKE PRIVATE KEY-----\nRUNNE_T1_FAKE_PEM_BODY_5e6f7a8b\n-----END RUNNE T1 FAKE PRIVATE KEY-----";
pub(super) const PROJ_INSTRUCTION: &str = "RUNNE_T1_PROJ_INSTRUCTION_CANARY_9d4e2a";
pub(super) const PROJ_SKILL: &str = "RUNNE_T1_PROJ_SKILL_CANARY_51b8c3";
pub(super) const PROJ_HOOK: &str = "RUNNE_T1_PROJ_HOOK_CANARY_77aa01";
pub(super) const PROJ_HELPER: &str = "RUNNE_T1_PROJ_HELPER_CANARY_2f0e9d";
pub(super) const PROJ_MCP: &str = "RUNNE_T1_PROJ_MCP_CANARY_c4b6f8";
pub(super) const PROJ_FILE: &str = "RUNNE_T1_PROJ_FILE_CANARY_8ad3e5";
pub(super) const PROJ_UNICODE_NFC: &str = "RUNNE_T1_PROJ_UNICODЕ_CANARY_3ab9";
pub(super) const PROJ_UNICODE_NFD: &str = "RUNNE_T1_PROJ_UNICODE_CANARY_3ab9";
pub(super) const PROJ_MANAGED_DENY: &str = "RUNNE_T1_MANAGED_DENY_CANARY_e17c44";

/// Secret-family patterns: material that must never appear in any sink.
#[allow(dead_code)] // consumed by sibling #[path] targets only
pub(super) fn secret_patterns() -> Vec<&'static str> {
    vec![
        FAKE_SECRET_API_KEY,
        FAKE_SECRET_BEARER,
        FAKE_SECRET_ENV,
        FAKE_SECRET_HEADER,
        FAKE_SECRET_BLOB,
        FAKE_SECRET_CRASH,
        FAKE_SECRET_PEM,
        CANARY,
        PROJ_UNICODE_NFC,
        PROJ_UNICODE_NFD,
        PROJ_MANAGED_DENY,
    ]
}

/// Project-content markers planted in readable file-channel files.
#[allow(dead_code)] // consumed by sibling #[path] targets only
pub(super) fn project_patterns() -> Vec<&'static str> {
    vec![
        PROJ_INSTRUCTION,
        PROJ_SKILL,
        PROJ_HOOK,
        PROJ_HELPER,
        PROJ_MCP,
        PROJ_FILE,
    ]
}

pub(super) fn scanner(patterns: &[&str]) -> SecretScanner {
    let mut reps: Vec<SecretRepresentation> = patterns
        .iter()
        .map(|pattern| SecretRepresentation {
            class: RepresentationClass::Raw,
            bytes: pattern.as_bytes().to_vec(),
        })
        .collect();
    let encoded: Vec<String> = patterns
        .iter()
        .map(|pattern| base64::engine::general_purpose::STANDARD.encode(pattern.as_bytes()))
        .collect();
    for encoded in &encoded {
        reps.push(SecretRepresentation {
            class: RepresentationClass::Base64,
            bytes: encoded.clone().into_bytes(),
        });
    }
    for encoded in &encoded {
        let unpadded = encoded.trim_end_matches('=');
        if unpadded != encoded.as_str() {
            reps.push(SecretRepresentation {
                class: RepresentationClass::Base64Unpadded,
                bytes: unpadded.as_bytes().to_vec(),
            });
        }
    }
    // SCAN-MARKER: the frozen marker prefix covers truncated copies of any
    // RUNNE_T1_FAKE value outside the scanner whitelist.
    reps.push(SecretRepresentation {
        class: RepresentationClass::Raw,
        bytes: b"RUNNE_T1_FAKE".to_vec(),
    });
    match SecretScanner::new(reps) {
        Ok(scanner) => scanner,
        Err(_) => panic!("scan patterns must build"),
    }
}

pub(super) fn scan_absent(scanner: &SecretScanner, sink: &str, bytes: &[u8]) {
    secret_scan::assert_reader_absent(scanner, sink, Cursor::new(bytes));
}

/// Byte-exact cross-check of the embedded constants against the frozen
/// fixtures (guards against transcription drift, including the NFC homoglyph).
#[allow(dead_code)] // consumed by sibling #[path] targets only
pub(super) fn assert_constants_match_frozen_fixtures() {
    let golden = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/golden/t1");
    let secrets: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(golden.join("fake-canary-secrets-v1.json")).expect("fixture"),
    )
    .expect("secrets fixture json");
    let value_of = |fixture: &serde_json::Value, id: &str, field: &str| -> String {
        fixture["canaries"]
            .as_array()
            .expect("canaries")
            .iter()
            .find(|canary| canary["id"].as_str() == Some(id))
            .expect("canary")[field]
            .as_str()
            .expect("string field")
            .to_owned()
    };
    assert_eq!(
        FAKE_SECRET_API_KEY,
        value_of(&secrets, "FAKE-SECRET-001", "value")
    );
    assert_eq!(
        FAKE_SECRET_BEARER,
        value_of(&secrets, "FAKE-SECRET-002", "value")
    );
    assert_eq!(
        FAKE_SECRET_ENV,
        value_of(&secrets, "FAKE-SECRET-003", "value")
    );
    assert_eq!(
        FAKE_SECRET_HEADER,
        value_of(&secrets, "FAKE-SECRET-004", "value")
    );
    assert_eq!(
        FAKE_SECRET_BLOB,
        value_of(&secrets, "FAKE-SECRET-005", "value")
    );
    assert_eq!(
        FAKE_SECRET_CRASH,
        value_of(&secrets, "FAKE-SECRET-006", "value")
    );
    assert_eq!(
        FAKE_SECRET_PEM,
        value_of(&secrets, "FAKE-SECRET-007", "value")
    );
    let content: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(golden.join("project-content-canaries-v1.json")).expect("fixture"),
    )
    .expect("content fixture json");
    for (constant, id) in [
        (PROJ_INSTRUCTION, "PROJ-CANARY-INSTRUCTION"),
        (PROJ_SKILL, "PROJ-CANARY-SKILL"),
        (PROJ_HOOK, "PROJ-CANARY-HOOK"),
        (PROJ_HELPER, "PROJ-CANARY-HELPER"),
        (PROJ_MCP, "PROJ-CANARY-MCP"),
        (PROJ_FILE, "PROJ-CANARY-FILE"),
        (PROJ_UNICODE_NFC, "PROJ-CANARY-UNICODE-NFC"),
        (PROJ_UNICODE_NFD, "PROJ-CANARY-UNICODE-NFD"),
        (PROJ_MANAGED_DENY, "PROJ-CANARY-MANAGED-DENY"),
    ] {
        assert_eq!(constant, value_of(&content, id, "marker"));
    }
}
