#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    Digest, DurableFixtureThresholdContext, ThresholdFixtureStoreBinding,
    ThresholdVerificationState,
};
use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

#[test]
fn durable_threshold_context_rejects_a_second_live_path_owner() {
    let path = std::path::Path::new("/dev/shm")
        .join(format!("gocode-threshold-lock-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let binding =
        ThresholdFixtureStoreBinding::new(Digest::fixture([7; 32]), "fixture-v1", 1).unwrap();
    let owner = DurableFixtureThresholdContext::create(&path, binding.clone(), state(), 1).unwrap();

    assert!(DurableFixtureThresholdContext::reopen(&path, binding).is_err());

    drop(owner);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn killed_threshold_owner_releases_the_os_lock() {
    if let Ok(path) = std::env::var("GOCODE_DURABLE_LOCK_CHILD") {
        let path = std::path::PathBuf::from(path);
        let _owner = DurableFixtureThresholdContext::reopen(&path, binding()).unwrap();
        std::fs::write(path.with_extension("ready"), b"ready").unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    let path = std::path::Path::new("/dev/shm").join(format!(
        "gocode-threshold-killed-lock-{}",
        std::process::id()
    ));
    let ready = path.with_extension("ready");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&ready);
    let owner = DurableFixtureThresholdContext::create(&path, binding(), state(), 1).unwrap();
    drop(owner);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "killed_threshold_owner_releases_the_os_lock"])
        .env("GOCODE_DURABLE_LOCK_CHILD", &path)
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.exists());
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(DurableFixtureThresholdContext::reopen(&path, binding()).is_ok());
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(path.with_extension("lease")).unwrap();
    std::fs::remove_file(ready).unwrap();
}

fn binding() -> ThresholdFixtureStoreBinding {
    ThresholdFixtureStoreBinding::new(Digest::fixture([7; 32]), "fixture-v1", 1).unwrap()
}

fn state() -> ThresholdVerificationState {
    ThresholdVerificationState {
        versions: ["root", "targets", "snapshot", "timestamp"]
            .into_iter()
            .map(|role| (role.into(), 1))
            .collect(),
        rollback_floor: 1,
        revocation_floor: 1,
        frozen: false,
        generation: 1,
        root_keys: keys("r", 1),
        targets_keys: keys("t", 4),
        snapshot_key: ("snapshot".into(), [7; 32]),
        timestamp_key: ("timestamp".into(), [8; 32]),
        channel_policy_id: Some("fixture-channel-policy".into()),
        role_bodies: BTreeMap::new(),
        role_digests: BTreeMap::new(),
    }
}

fn keys(prefix: &str, start: u8) -> BTreeMap<String, [u8; 32]> {
    (0..3)
        .map(|offset| (format!("{prefix}{}", offset + 1), [start + offset; 32]))
        .collect()
}
