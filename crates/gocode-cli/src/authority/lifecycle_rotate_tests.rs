use std::{collections::BTreeMap, sync::Mutex};

use super::tests::{FakeClock, FakeFiles, FakeRng, FakeStore, FakeTty, runner};
use super::{AuthorityCommandRunner, AuthorityFiles, AuthorityTty, InitRequest, RotateRequest};
use crate::CliError;
use gocode_secure_store::ProjectOwnerKeyStore;
use sha2::{Digest as _, Sha256};

struct RecordingTty {
    fail: bool,
    calls: Mutex<Vec<(String, String)>>,
}

impl RecordingTty {
    fn accepting() -> Self {
        Self {
            fail: false,
            calls: Mutex::new(vec![]),
        }
    }
    fn rejecting() -> Self {
        Self {
            fail: true,
            calls: Mutex::new(vec![]),
        }
    }
}

impl AuthorityTty for RecordingTty {
    fn confirm(&self, display: &str, challenge: &str) -> Result<(), CliError> {
        self.calls
            .lock()
            .expect("calls")
            .push((display.into(), challenge.into()));
        if self.fail {
            Err(CliError::AuthorityConfirmationFailed)
        } else {
            Ok(())
        }
    }
}

fn files() -> FakeFiles {
    FakeFiles {
        fail_on_write: Mutex::new(None),
        write_count: Mutex::new(0),
        fail_reads_after_write: false,
        bytes: Mutex::new(BTreeMap::new()),
    }
}

fn initialized(store: &FakeStore, files: &FakeFiles) {
    let mut rng = FakeRng;
    runner(store, files, &mut rng)
        .init(InitRequest {
            trust_out: "docs/trust.json".into(),
        })
        .expect("init");
}

#[test]
fn rotate_advances_the_key_and_floor_together_after_artifact_rereads() {
    let store = FakeStore::new();
    let files = files();
    initialized(&store, &files);
    let before = store
        .read_active_ref("gocode")
        .expect("read")
        .expect("active");
    let floor = store
        .read_anchor_floor("gocode")
        .expect("read")
        .expect("floor");
    let mut rng = FakeRng;
    let output = AuthorityCommandRunner::new(&store, &(), &FakeTty, &mut rng, &FakeClock, &files)
        .rotate(RotateRequest {
            trust_config: "docs/trust.json".into(),
            rotation_out: "docs/evidence/rotation.json".into(),
            successor_trust_out: "docs/successor-trust.json".into(),
        })
        .expect("rotate");
    assert_eq!(output.artifacts.len(), 2);
    assert_eq!(output.artifacts[0].kind, "rotation");
    assert_eq!(output.artifacts[0].path, "docs/evidence/rotation.json");
    let rotation_digest: [u8; 32] = Sha256::digest(
        files
            .read_repo_public("docs/evidence/rotation.json")
            .expect("rotation"),
    )
    .into();
    assert_eq!(output.artifacts[0].sha256, rotation_digest);
    assert_eq!(output.artifacts[1].kind, "successor-trust");
    assert_eq!(output.artifacts[1].path, "docs/successor-trust.json");
    let successor_digest: [u8; 32] = Sha256::digest(
        files
            .read_repo_public("docs/successor-trust.json")
            .expect("successor"),
    )
    .into();
    assert_eq!(output.artifacts[1].sha256, successor_digest);
    assert!(
        String::from_utf8(output.stdout)
            .expect("public display")
            .contains("\"operation\":\"rotate\"")
    );
    let after = store
        .read_active_ref("gocode")
        .expect("read")
        .expect("active");
    let new_floor = store
        .read_anchor_floor("gocode")
        .expect("read")
        .expect("floor");
    assert_eq!(after.key_epoch(), before.key_epoch() + 1);
    assert_eq!(new_floor.highest_key_epoch(), floor.highest_key_epoch() + 1);
}

#[test]
fn rotate_second_artifact_failure_leaves_old_store_state() {
    let store = FakeStore::new();
    let files = files();
    initialized(&store, &files);
    let old_key = store.read_active_ref("gocode").expect("read");
    let old_floor = store.read_anchor_floor("gocode").expect("read");
    *files.fail_on_write.lock().expect("failure") = Some(3);
    let mut rng = FakeRng;
    assert!(
        AuthorityCommandRunner::new(&store, &(), &FakeTty, &mut rng, &FakeClock, &files)
            .rotate(RotateRequest {
                trust_config: "docs/trust.json".into(),
                rotation_out: "docs/evidence/rotation.json".into(),
                successor_trust_out: "docs/successor-trust.json".into()
            })
            .is_err()
    );
    assert_eq!(store.read_active_ref("gocode").expect("read"), old_key);
    assert_eq!(store.read_anchor_floor("gocode").expect("read"), old_floor);
    assert!(
        files
            .read_repo_public("docs/evidence/rotation.json")
            .is_ok()
    );
    assert!(files.read_repo_public("docs/successor-trust.json").is_err());
}

#[test]
fn rotate_confirmation_failure_leaves_old_state_and_writes_no_outputs() {
    let store = FakeStore::new();
    let files = files();
    initialized(&store, &files);
    let before = store.read_active_ref("gocode").expect("read");
    let floor = store.read_anchor_floor("gocode").expect("read");
    let tty = RecordingTty::rejecting();
    let mut rng = FakeRng;

    assert!(
        AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
            .rotate(RotateRequest {
                trust_config: "docs/trust.json".into(),
                rotation_out: "docs/evidence/rotation.json".into(),
                successor_trust_out: "docs/successor-trust.json".into(),
            })
            .is_err()
    );
    assert_eq!(store.read_active_ref("gocode").expect("read"), before);
    assert_eq!(store.read_anchor_floor("gocode").expect("read"), floor);
    assert!(
        files
            .read_repo_public("docs/evidence/rotation.json")
            .is_err()
    );
    assert!(files.read_repo_public("docs/successor-trust.json").is_err());
}

#[test]
fn rotate_review_binds_both_output_paths_and_recomputed_output_set() {
    let store = FakeStore::new();
    let files = files();
    initialized(&store, &files);
    let tty = RecordingTty::accepting();
    let mut rng = FakeRng;
    let output = AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
        .rotate(RotateRequest {
            trust_config: "docs/trust.json".into(),
            rotation_out: "docs/evidence/rotation.json".into(),
            successor_trust_out: "docs/successor-trust.json".into(),
        })
        .expect("rotate");
    let calls = tty.calls.lock().expect("calls");
    let (display, challenge) = calls.first().expect("confirmation");
    assert!(display.contains("docs/evidence/rotation.json"));
    assert!(display.contains("docs/successor-trust.json"));
    assert!(display.contains("repository-artifact-set-v1"));
    assert!(display.ends_with(&format!("review_sha256={}\n", sha256_from_display(display))));
    assert_eq!(challenge, &sha256_from_display(display)[52..]);
    assert_eq!(output.artifacts.len(), 2);
    drop(calls);
}

fn sha256_from_display(display: &str) -> String {
    display
        .strip_suffix('\n')
        .and_then(|value| value.rsplit_once("\nreview_sha256="))
        .map(|(_, digest)| digest.into())
        .expect("review digest")
}

#[test]
fn rotate_rejects_different_existing_artifact_without_advancing_store() {
    let store = FakeStore::new();
    let files = files();
    initialized(&store, &files);
    files.bytes.lock().expect("bytes").insert(
        "docs/evidence/rotation.json".into(),
        b"different\n".to_vec(),
    );
    let before = store.read_active_ref("gocode").expect("read");
    let mut rng = FakeRng;

    assert!(
        AuthorityCommandRunner::new(&store, &(), &FakeTty, &mut rng, &FakeClock, &files)
            .rotate(RotateRequest {
                trust_config: "docs/trust.json".into(),
                rotation_out: "docs/evidence/rotation.json".into(),
                successor_trust_out: "docs/successor-trust.json".into(),
            })
            .is_err()
    );
    assert_eq!(store.read_active_ref("gocode").expect("read"), before);
}

#[test]
fn rotate_restart_resumes_the_same_pending_key_after_partial_publication() {
    let store = FakeStore::new();
    let files = files();
    initialized(&store, &files);
    *files.fail_on_write.lock().expect("failure") = Some(3);
    let request = RotateRequest {
        trust_config: "docs/trust.json".into(),
        rotation_out: "docs/evidence/rotation.json".into(),
        successor_trust_out: "docs/successor-trust.json".into(),
    };
    let mut rng = FakeRng;
    assert!(
        AuthorityCommandRunner::new(&store, &(), &FakeTty, &mut rng, &FakeClock, &files)
            .rotate(request)
            .is_err()
    );
    let mut rng = FakeRng;
    let result = AuthorityCommandRunner::new(&store, &(), &FakeTty, &mut rng, &FakeClock, &files)
        .rotate(RotateRequest {
            trust_config: "docs/trust.json".into(),
            rotation_out: "docs/evidence/rotation.json".into(),
            successor_trust_out: "docs/successor-trust.json".into(),
        })
        .expect("identical retry");
    assert_eq!(result.artifacts.len(), 2);
    assert_eq!(
        store
            .read_active_ref("gocode")
            .expect("read")
            .expect("active")
            .key_epoch(),
        2
    );
}
