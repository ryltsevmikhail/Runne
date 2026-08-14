#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    Digest, DurableFixturePromotionStore, ThresholdFixtureStoreBinding,
};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "verify_signed/support.rs"]
mod signing_support;
#[path = "canonical_wire/support.rs"]
mod support;
mod verified_stage_support;

#[test]
fn reopen_rejects_self_consistent_snapshot_field_substitutions() {
    let path = std::path::Path::new("/dev/shm")
        .join(format!("gocode-snapshot-validation-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (memory, id, _) = signing_support::signing_authorized();
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let store =
        DurableFixturePromotionStore::create_from_in_memory(&path, binding.clone(), &memory, &id)
            .unwrap();
    let snapshot = store.snapshot(&id).unwrap();
    drop(store);

    for (field, value) in [
        ("promotion_id", "other"),
        ("state", "rc1_review"),
        ("revision", "9"),
        ("candidate_binding_sha256", &"bb".repeat(32)),
        ("candidate_sha256", &"bb".repeat(32)),
        ("previous_snapshot_sha256", &"bb".repeat(32)),
        ("command_fingerprint_sha256", &"bb".repeat(32)),
        ("effect_generation", "9"),
    ] {
        std::fs::write(&path, source(&binding, &memory, &id)).unwrap();
        rewrite_snapshot(&path, &snapshot, field, value);
        assert!(
            DurableFixturePromotionStore::reopen(&path, binding.clone()).is_err(),
            "{field}"
        );
    }
    std::fs::remove_file(path).unwrap();
}

fn rewrite_snapshot(
    path: &std::path::Path,
    snapshot: &gocode_release_authority::PromotionStateSnapshot,
    field: &str,
    value: &str,
) {
    let mut wire: serde_json::Value = serde_json::from_slice(&snapshot.bytes).unwrap();
    wire[field] = value.parse().map_or_else(
        |_| serde_json::Value::String(value.into()),
        serde_json::Value::Number,
    );
    let mut bytes = serde_json::to_vec(&wire).unwrap();
    bytes.push(b'\n');
    let digest = format!("{:x}", Sha256::digest(&bytes[..bytes.len() - 1]));
    let old = hex(&snapshot.bytes);
    let mut durable = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
    durable = durable.replacen(&old, &hex(&bytes), 1);
    durable = durable.replacen(&snapshot.digest.to_hex(), &digest, 1);
    std::fs::write(path, durable).unwrap();
}

fn source(
    binding: &ThresholdFixtureStoreBinding,
    memory: &gocode_release_authority::InMemoryPromotionStore,
    id: &gocode_release_authority::PromotionId,
) -> Vec<u8> {
    let path = std::path::Path::new("/dev/shm")
        .join(format!("gocode-snapshot-source-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let store =
        DurableFixturePromotionStore::create_from_in_memory(&path, binding.clone(), memory, id)
            .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    drop(store);
    std::fs::remove_file(path).unwrap();
    bytes
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
