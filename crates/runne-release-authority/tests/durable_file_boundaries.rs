#![cfg(all(feature = "fixture-only", unix))]

use runne_release_authority::{
    Digest, DurableFixturePromotionStore, DurableFixtureThresholdContext,
    ThresholdFixtureStoreBinding, ThresholdVerificationState,
};
use std::os::unix::fs::{PermissionsExt, symlink};

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "verify_signed/support.rs"]
#[allow(dead_code)]
mod signing_support;
#[path = "canonical_wire/support.rs"]
mod support;
#[path = "threshold_support.rs"]
mod threshold_support;
mod verified_stage_support;

#[test]
fn promotion_file_reopen_rejects_corrupt_and_unsafe_boundaries() {
    for case in [
        "truncated",
        "corrupt",
        "unknown",
        "duplicate",
        "reordered",
        "symlink",
        "directory",
        "mode",
    ] {
        let path = promotion_path(case);
        let binding = binding();
        let (memory, id, _) = signing_support::signing_authorized();
        let store = DurableFixturePromotionStore::create_from_in_memory(
            &path,
            binding.clone(),
            &memory,
            &id,
        )
        .unwrap();
        drop(store);
        mutate(&path, case, true);
        assert!(
            DurableFixturePromotionStore::reopen(&path, binding).is_err(),
            "{case}"
        );
        cleanup(&path);
    }
}

#[test]
fn threshold_file_reopen_rejects_corrupt_and_unsafe_boundaries() {
    for case in [
        "truncated",
        "corrupt",
        "unknown",
        "duplicate",
        "reordered",
        "symlink",
        "directory",
        "mode",
    ] {
        let path = threshold_path(case);
        let context = DurableFixtureThresholdContext::create(&path, binding(), state(), 1).unwrap();
        drop(context);
        mutate(&path, case, false);
        assert!(
            DurableFixtureThresholdContext::reopen(&path, binding()).is_err(),
            "{case}"
        );
        cleanup(&path);
    }
}

#[test]
fn both_canonical_durable_files_reopen_when_unchanged() {
    let promotion = promotion_path("valid");
    let threshold = threshold_path("valid");
    let (memory, id, _) = signing_support::signing_authorized();
    let store =
        DurableFixturePromotionStore::create_from_in_memory(&promotion, binding(), &memory, &id)
            .unwrap();
    let context =
        DurableFixtureThresholdContext::create(&threshold, binding(), state(), 1).unwrap();
    drop(store);
    drop(context);
    assert!(DurableFixturePromotionStore::reopen(&promotion, binding()).is_ok());
    assert!(DurableFixtureThresholdContext::reopen(&threshold, binding()).is_ok());
    cleanup(&promotion);
    cleanup(&threshold);
}

fn mutate(path: &std::path::Path, case: &str, json: bool) {
    match case {
        "truncated" => std::fs::write(path, b"bad").unwrap(),
        "corrupt" => std::fs::write(path, b"\xff").unwrap(),
        "unknown" => {
            let mut b = std::fs::read(path).unwrap();
            if json {
                b.pop();
                b.extend_from_slice(b",\"unknown\":1}\n");
            } else {
                b.extend_from_slice(b"unknown=1\n");
            }
            std::fs::write(path, b).unwrap();
        }
        "duplicate" => {
            let mut b = std::fs::read(path).unwrap();
            if json {
                b.pop();
                b.extend_from_slice(
                    b",\"schema_version\":\"gocode.release.durable-promotion-store/1\"}\n",
                );
            } else {
                b.extend_from_slice(b"ack_count=0\n");
            }
            std::fs::write(path, b).unwrap();
        }
        "reordered" => {
            let mut text = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
            if json {
                text = text
                    .replacen("{\"schema_version", "{\"version", 1)
                    .replacen("\",\"bootstrap", ",\"schema_version\",\"bootstrap", 1);
            } else {
                text = text.replacen("bootstrap=", "profile=fixture-v1\nbootstrap=", 1);
            }
            std::fs::write(path, text).unwrap();
        }
        "symlink" => {
            std::fs::remove_file(path).unwrap();
            symlink("/dev/null", path).unwrap();
        }
        "directory" => {
            std::fs::remove_file(path).unwrap();
            std::fs::create_dir(path).unwrap();
        }
        "mode" => {
            let mut p = std::fs::metadata(path).unwrap().permissions();
            p.set_mode(0o644);
            std::fs::set_permissions(path, p).unwrap();
        }
        _ => unreachable!(),
    }
}
fn binding() -> ThresholdFixtureStoreBinding {
    ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap()
}
fn state() -> ThresholdVerificationState {
    ThresholdVerificationState {
        versions: ["root", "targets", "snapshot", "timestamp"]
            .into_iter()
            .map(|x| (x.into(), 1))
            .collect(),
        rollback_floor: 1,
        revocation_floor: 1,
        frozen: false,
        generation: 1,
        root_keys: threshold_support::threshold_keyset("r"),
        targets_keys: threshold_support::threshold_keyset("t"),
        snapshot_key: (
            "snapshot".into(),
            threshold_support::threshold_public_key("snapshot"),
        ),
        timestamp_key: (
            "timestamp".into(),
            threshold_support::threshold_public_key("timestamp"),
        ),
        channel_policy_id: Some("fixture-channel-policy".into()),
        role_bodies: std::collections::BTreeMap::new(),
        role_digests: std::collections::BTreeMap::new(),
    }
}
fn promotion_path(case: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "runne-promotion-boundary-{case}-{}",
        std::process::id()
    ))
}
fn threshold_path(case: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "runne-threshold-boundary-{case}-{}",
        std::process::id()
    ))
}
fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
}
