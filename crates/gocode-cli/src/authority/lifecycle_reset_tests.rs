use std::{collections::BTreeMap, path::Path, sync::Mutex};

use gocode_project_owner_authority::{
    GitSubject, ProjectOwnerTrustConfigV1, PurposeProfileV1, key_fingerprint,
};
use gocode_secure_store::ProjectOwnerKeyStore;

use crate::authority::review::AuthorityReviewV1;

use super::tests::{FakeClock, FakeFiles, FakeRng, FakeStore, runner};
use super::{
    AuthorityClock, AuthorityCommandRunner, AuthorityFiles, AuthorityGitResolver, AuthorityRng,
    AuthorityTty, InitRequest, TrustResetRequest,
};
use crate::CliError;

struct PanicGit;
impl AuthorityGitResolver for PanicGit {
    fn capture_current(
        &self,
        _: &PurposeProfileV1,
    ) -> Result<super::super::git::CapturedSubject, CliError> {
        panic!("trust reset must not capture Git")
    }
    fn resolve_subject(
        &self,
        _: &GitSubject,
        _: &PurposeProfileV1,
    ) -> Result<super::super::git::CapturedSubject, CliError> {
        panic!("trust reset must not resolve Git")
    }
    fn repository_root(&self) -> &Path {
        panic!("trust reset must not read repository root")
    }
}

struct PanicRng;
impl AuthorityRng for PanicRng {}
struct PanicClock;
impl AuthorityClock for PanicClock {
    fn utc_rfc3339_seconds(&self) -> Result<String, CliError> {
        panic!("trust reset must not read the clock")
    }
}

struct RecordingTty {
    accept: bool,
    calls: Mutex<Vec<(String, String)>>,
}

impl AuthorityTty for RecordingTty {
    fn confirm(&self, display: &str, challenge: &str) -> Result<(), CliError> {
        self.calls
            .lock()
            .expect("calls")
            .push((display.into(), challenge.into()));
        if self.accept {
            Ok(())
        } else {
            Err(CliError::AuthorityConfirmationFailed)
        }
    }
}

fn fixture_files() -> FakeFiles {
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

fn expected_ack(files: &FakeFiles) -> String {
    let trust = ProjectOwnerTrustConfigV1::from_json(
        &files.read_repo_public("docs/trust.json").expect("trust"),
    )
    .expect("trust config");
    AuthorityReviewV1 {
        schema_version: "gocode.authority.cli-review/1".into(),
        operation: "trust-reset".into(),
        repository_id: "gocode".into(),
        purpose: None,
        profile: None,
        subject: None,
        documents: vec![],
        trust_config_sha256: hex(&trust.sha256().expect("digest")),
        key_id: hex(&trust.key_id),
        key_fingerprint: hex(&key_fingerprint(&trust.public_key)),
        key_epoch: trust.epoch,
        issued_at: None,
        signing_transcript_sha256: None,
        output: None,
        rotation: None,
        backup: None,
        continuity: "discontinuity".into(),
    }
    .confirmation_challenge()
    .expect("challenge")
}

#[test]
fn reset_requires_exact_compromise_acknowledgement_before_confirmation_or_state_change() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    let exact = expected_ack(&files);
    let upper = exact.to_uppercase();
    assert_ne!(upper, exact, "fixed review digest includes lower hex");
    for acknowledgement in [
        String::new(),
        "COMPROMISE-000000000000".into(),
        upper,
        format!("{exact}x"),
    ] {
        let store = FakeStore::new();
        let files = fixture_files();
        initialized(&store, &files);
        let tty = RecordingTty {
            accept: true,
            calls: Mutex::new(vec![]),
        };
        let mut rng = FakeRng;
        assert!(
            AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
                .trust_reset(TrustResetRequest {
                    trust_config: "docs/trust.json".into(),
                    acknowledgement
                })
                .is_err()
        );
        assert!(store.read_active_ref("gocode").expect("active").is_some());
        assert!(store.read_anchor_floor("gocode").expect("floor").is_some());
        assert_eq!(store.state.lock().expect("state").reset_calls, 0);
        assert!(tty.calls.lock().expect("calls").is_empty());
    }
}

#[test]
fn reset_rejection_retains_state_and_never_writes() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    let tty = RecordingTty {
        accept: false,
        calls: Mutex::new(vec![]),
    };
    let mut rng = FakeRng;
    let writes_before = *files.write_count.lock().expect("writes");
    assert!(
        AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
            .trust_reset(TrustResetRequest {
                trust_config: "docs/trust.json".into(),
                acknowledgement: expected_ack(&files)
            })
            .is_err()
    );
    assert!(store.read_active_ref("gocode").expect("active").is_some());
    assert!(store.read_anchor_floor("gocode").expect("floor").is_some());
    assert_eq!(store.state.lock().expect("state").reset_calls, 0);
    assert_eq!(*files.write_count.lock().expect("writes"), writes_before);
}

#[test]
fn reset_rejects_trust_active_and_floor_mismatches_before_store_reset() {
    for mismatch in ["trust", "active", "floor"] {
        let store = FakeStore::new();
        let files = fixture_files();
        initialized(&store, &files);
        let acknowledgement = expected_ack(&files);
        match mismatch {
            "trust" => {
                files
                    .bytes
                    .lock()
                    .expect("bytes")
                    .insert("docs/trust.json".into(), b"not json\n".to_vec());
            }
            "active" => {
                store.state.lock().expect("state").active = None;
            }
            "floor" => {
                store.state.lock().expect("state").floor = None;
            }
            _ => unreachable!(),
        }
        let tty = RecordingTty {
            accept: true,
            calls: Mutex::new(vec![]),
        };
        let mut rng = FakeRng;
        assert!(
            AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
                .trust_reset(TrustResetRequest {
                    trust_config: "docs/trust.json".into(),
                    acknowledgement
                })
                .is_err()
        );
        assert_eq!(store.state.lock().expect("state").reset_calls, 0);
        assert!(tty.calls.lock().expect("calls").is_empty());
    }
}

#[test]
fn reset_removes_exact_active_key_and_floor_after_matching_tty_acknowledgement() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    let acknowledgement = expected_ack(&files);
    let tty = RecordingTty {
        accept: true,
        calls: Mutex::new(vec![]),
    };
    let mut rng = PanicRng;
    let writes_before = *files.write_count.lock().expect("writes");
    let output =
        AuthorityCommandRunner::new(&store, &PanicGit, &tty, &mut rng, &PanicClock, &files)
            .trust_reset(TrustResetRequest {
                trust_config: "docs/trust.json".into(),
                acknowledgement: acknowledgement.clone(),
            })
            .expect("reset");
    assert_eq!(
        output.stdout,
        b"TRUST_RESET_REQUIRES_NEW_GENESIS_AND_OUT_OF_BAND_REBOOTSTRAP\n"
    );
    assert!(output.artifacts.is_empty());
    assert_eq!(*files.write_count.lock().expect("writes"), writes_before);
    assert!(store.read_active_ref("gocode").expect("active").is_none());
    assert!(store.read_anchor_floor("gocode").expect("floor").is_none());
    assert_eq!(store.state.lock().expect("state").reset_calls, 1);
    let calls = tty.calls.lock().expect("calls");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, acknowledgement);
    assert!(calls[0].0.contains("\"operation\":\"trust-reset\""));
    drop(calls);
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(value, "{byte:02x}").expect("String");
    }
    value
}
