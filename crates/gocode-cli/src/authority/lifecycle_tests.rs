use ed25519_dalek::SigningKey;
use gocode_project_owner_authority::verify_genesis;
use gocode_secure_store::{ProjectOwnerKeyRef, ProjectOwnerKeyStore};
use std::{collections::BTreeMap, sync::Mutex};

pub(super) use super::test_pending::runner;
pub(super) use super::test_support::*;
use super::{AuthorityCommandRunner, AuthorityFiles, AuthorityTty, CommandOutput, InitRequest};
use crate::CliError;

struct RejectingTty;
impl AuthorityTty for RejectingTty {
    fn confirm(&self, _: &str, _: &str) -> Result<(), CliError> {
        Err(CliError::AuthorityConfirmationFailed)
    }
}

#[test]
fn init_confirms_publishes_and_commits_the_matching_key_and_floor() {
    let store = FakeStore::new();
    let files = FakeFiles {
        fail_on_write: Mutex::new(None),
        write_count: Mutex::new(0),
        fail_reads_after_write: false,
        bytes: Mutex::new(BTreeMap::new()),
    };
    let mut rng = FakeRng;
    let CommandOutput { stdout, artifacts } = runner(&store, &files, &mut rng)
        .init(InitRequest {
            trust_out: "docs/trust.json".into(),
        })
        .expect("init");
    assert!(!stdout.is_empty());
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].kind, "trust-config");
    let active = store
        .read_active_ref("gocode")
        .expect("read")
        .expect("active");
    let floor = store
        .read_anchor_floor("gocode")
        .expect("read")
        .expect("floor");
    assert_eq!(active.key_epoch(), 1);
    assert_eq!(floor.highest_key_epoch(), 1);
    let trust = gocode_project_owner_authority::ProjectOwnerTrustConfigV1::from_json(
        &files.read_repo_public("docs/trust.json").expect("artifact"),
    )
    .expect("trust");
    verify_genesis(&trust).expect("verified");
}

#[test]
fn init_write_failure_leaves_key_and_floor_absent() {
    let store = FakeStore::new();
    let files = FakeFiles {
        fail_on_write: Mutex::new(Some(1)),
        write_count: Mutex::new(0),
        fail_reads_after_write: false,
        bytes: Mutex::new(BTreeMap::new()),
    };
    let mut rng = FakeRng;
    assert!(
        runner(&store, &files, &mut rng)
            .init(InitRequest {
                trust_out: "docs/trust.json".into()
            })
            .is_err()
    );
    assert!(store.read_active_ref("gocode").expect("read").is_none());
    assert!(store.read_anchor_floor("gocode").expect("read").is_none());
}

#[test]
fn init_retry_after_rejected_confirmation_reuses_pending_genesis_key() {
    let store = FakeStore::new();
    let files = fixture_files();
    let mut rng = FakeRng;
    let request = || InitRequest {
        trust_out: "docs/trust.json".into(),
    };
    assert!(
        AuthorityCommandRunner::new(&store, &(), &RejectingTty, &mut rng, &FakeClock, &files)
            .init(request())
            .is_err()
    );
    let pending_key = store
        .state
        .lock()
        .expect("state")
        .pending
        .as_ref()
        .expect("pending")
        .reference
        .clone();
    let mut rng = FakeRng;
    runner(&store, &files, &mut rng)
        .init(request())
        .expect("resumed init");
    assert_eq!(
        store.read_active_ref("gocode").expect("read"),
        Some(pending_key)
    );
}

#[test]
fn init_retry_after_published_artifact_reuses_exact_bytes_and_commits() {
    let store = FakeStore::new();
    let files = fixture_files();
    store.state.lock().expect("state").fail_next_commit = true;
    let mut rng = FakeRng;
    let request = || InitRequest {
        trust_out: "docs/trust.json".into(),
    };
    assert!(runner(&store, &files, &mut rng).init(request()).is_err());
    let published = files
        .read_repo_public("docs/trust.json")
        .expect("published");
    assert!(store.read_active_ref("gocode").expect("read").is_none());
    let mut rng = FakeRng;
    runner(&store, &files, &mut rng)
        .init(request())
        .expect("resumed init");
    assert_eq!(
        files.read_repo_public("docs/trust.json").expect("final"),
        published
    );
}

#[test]
fn init_retry_rejects_mismatching_existing_artifact_without_activation() {
    let store = FakeStore::new();
    let files = fixture_files();
    let mut rng = FakeRng;
    assert!(
        AuthorityCommandRunner::new(&store, &(), &RejectingTty, &mut rng, &FakeClock, &files)
            .init(InitRequest {
                trust_out: "docs/trust.json".into()
            })
            .is_err()
    );
    files
        .bytes
        .lock()
        .expect("bytes")
        .insert("docs/trust.json".into(), b"different\n".to_vec());
    let mut rng = FakeRng;
    assert!(
        runner(&store, &files, &mut rng)
            .init(InitRequest {
                trust_out: "docs/trust.json".into()
            })
            .is_err()
    );
    assert!(store.read_active_ref("gocode").expect("read").is_none());
}

#[test]
fn init_retry_rejects_mismatching_pending_record_without_activation() {
    let store = FakeStore::new();
    let files = fixture_files();
    let mut rng = FakeRng;
    assert!(
        AuthorityCommandRunner::new(&store, &(), &RejectingTty, &mut rng, &FakeClock, &files)
            .init(InitRequest {
                trust_out: "docs/trust.json".into()
            })
            .is_err()
    );
    let mismatch = ProjectOwnerKeyRef::new(
        "gocode",
        SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
        1,
    )
    .expect("mismatch");
    store
        .state
        .lock()
        .expect("state")
        .pending
        .as_mut()
        .expect("pending")
        .expected_active = Some(mismatch);
    let mut rng = FakeRng;
    assert!(
        runner(&store, &files, &mut rng)
            .init(InitRequest {
                trust_out: "docs/trust.json".into()
            })
            .is_err()
    );
    assert!(store.read_active_ref("gocode").expect("read").is_none());
}

#[test]
fn init_does_not_reopen_after_publication_commit() {
    let store = FakeStore::new();
    let mut files = fixture_files();
    files.fail_reads_after_write = true;
    let mut rng = FakeRng;
    runner(&store, &files, &mut rng)
        .init(InitRequest {
            trust_out: "docs/trust.json".into(),
        })
        .expect("committed init");
    assert!(
        files
            .bytes
            .lock()
            .expect("bytes")
            .contains_key("docs/trust.json")
    );
}

fn fixture_files() -> FakeFiles {
    FakeFiles {
        fail_on_write: Mutex::new(None),
        write_count: Mutex::new(0),
        fail_reads_after_write: false,
        bytes: Mutex::new(BTreeMap::new()),
    }
}

#[test]
fn init_rejects_unsafe_output_before_pending_key_creation() {
    for path in ["/tmp/trust.json", "../trust.json"] {
        let store = FakeStore::new();
        let files = FakeFiles {
            fail_on_write: Mutex::new(None),
            write_count: Mutex::new(0),
            fail_reads_after_write: false,
            bytes: Mutex::new(BTreeMap::new()),
        };
        let mut rng = FakeRng;
        assert!(
            runner(&store, &files, &mut rng)
                .init(InitRequest {
                    trust_out: path.into()
                })
                .is_err()
        );
        let state = store.state.lock().expect("state");
        assert!(state.active.is_none() && state.floor.is_none() && state.pending_token.is_none());
        drop(state);
    }
}
