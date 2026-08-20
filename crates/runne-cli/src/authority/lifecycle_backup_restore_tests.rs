use std::{collections::BTreeMap, sync::Mutex};

use runne_secure_store::ProjectOwnerKeyStore;
use zeroize::Zeroizing;

use super::tests::{FakeClock, FakeFiles, FakeRng, FakeStore, runner};
use super::{
    AuthorityCommandRunner, AuthorityFiles, AuthorityTty, BackupRequest, InitRequest,
    RestoreRequest,
};
use crate::CliError;

#[path = "lifecycle_backup_restore_restore_tests.rs"]
mod restore_cases;

struct HiddenTty {
    entries: Mutex<Vec<Vec<u8>>>,
}

impl HiddenTty {
    fn new(entries: &[&[u8]]) -> Self {
        Self {
            entries: Mutex::new(entries.iter().map(|entry| entry.to_vec()).collect()),
        }
    }
}

impl AuthorityTty for HiddenTty {
    fn confirm(&self, _: &str, _: &str) -> Result<(), CliError> {
        Ok(())
    }

    fn read_hidden(&self, _: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
        let mut entries = self.entries.lock().expect("entries");
        if entries.is_empty() {
            return Err(CliError::AuthorityUnavailable);
        }
        Ok(Zeroizing::new(entries.remove(0)))
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

#[test]
fn backup_rejects_different_passphrases_before_export_or_output() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    let tty = HiddenTty::new(&[b"first", b"second"]);
    let mut rng = FakeRng;

    assert!(
        AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
            .backup(BackupRequest {
                trust_config: "docs/trust.json".into(),
                output: "/external/owner.backup.json".into(),
            })
            .is_err()
    );
    assert_eq!(store.state.lock().expect("state").backup_exports, 0);
    assert!(
        files
            .bounded_nofollow_read("/external/owner.backup.json")
            .is_err()
    );
}

#[test]
fn backup_writes_canonical_external_artifact_without_disclosing_path_or_secret() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    let tty = HiddenTty::new(&[b"correct horse", b"correct horse"]);
    let mut rng = FakeRng;

    let output = AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
        .backup(BackupRequest {
            trust_config: "docs/trust.json".into(),
            output: "/external/owner.backup.json".into(),
        })
        .expect("backup");
    let bytes = files
        .bounded_nofollow_read("/external/owner.backup.json")
        .expect("backup bytes");
    assert!(bytes.ends_with(b"\n"));
    assert_eq!(output.artifacts.len(), 1);
    assert_eq!(output.artifacts[0].path.len(), 64);
    let display = String::from_utf8(output.stdout).expect("display");
    assert!(!display.contains("/external/owner.backup.json"));
    assert!(!display.contains("correct horse"));
}

#[test]
fn backup_does_not_reopen_after_publication_commit() {
    let store = FakeStore::new();
    let mut files = fixture_files();
    initialized(&store, &files);
    *files.write_count.lock().expect("count") = 0;
    files.fail_reads_after_write = true;
    let tty = HiddenTty::new(&[b"correct horse", b"correct horse"]);
    let mut rng = FakeRng;
    AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
        .backup(BackupRequest {
            trust_config: "docs/trust.json".into(),
            output: "/external/owner.backup.json".into(),
        })
        .expect("committed backup");
    assert!(
        files
            .bytes
            .lock()
            .expect("bytes")
            .contains_key("/external/owner.backup.json")
    );
}

#[test]
fn restore_no_overwrite_restores_the_same_anchored_key_without_changing_floor() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    let backup_tty = HiddenTty::new(&[b"correct horse", b"correct horse"]);
    let mut rng = FakeRng;
    AuthorityCommandRunner::new(&store, &(), &backup_tty, &mut rng, &FakeClock, &files)
        .backup(BackupRequest {
            trust_config: "docs/trust.json".into(),
            output: "/external/owner.backup.json".into(),
        })
        .expect("backup");
    let floor = store.read_anchor_floor("gocode").expect("floor");
    store.state.lock().expect("state").active = None;
    let restore_tty = HiddenTty::new(&[b"correct horse"]);
    let mut rng = FakeRng;

    let output =
        AuthorityCommandRunner::new(&store, &(), &restore_tty, &mut rng, &FakeClock, &files)
            .restore(RestoreRequest {
                trust_config: "docs/trust.json".into(),
                input: "/external/owner.backup.json".into(),
                replace_active_trust: None,
                replace_active_key_id: None,
            })
            .expect("restore");
    assert!(store.read_active_ref("gocode").expect("active").is_some());
    assert_eq!(store.read_anchor_floor("gocode").expect("floor"), floor);
    assert_eq!(store.state.lock().expect("state").restores, 1);
    assert_eq!(output.artifacts[0].path.len(), 64);
}

#[test]
fn wrong_passphrase_and_ciphertext_tamper_have_the_same_stable_error() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    let backup_tty = HiddenTty::new(&[b"correct horse", b"correct horse"]);
    let mut rng = FakeRng;
    AuthorityCommandRunner::new(&store, &(), &backup_tty, &mut rng, &FakeClock, &files)
        .backup(BackupRequest {
            trust_config: "docs/trust.json".into(),
            output: "/external/owner.backup.json".into(),
        })
        .expect("backup");
    store.state.lock().expect("state").active = None;
    let wrong_tty = HiddenTty::new(&[b"wrong passphrase"]);
    let mut rng = FakeRng;
    let wrong = AuthorityCommandRunner::new(&store, &(), &wrong_tty, &mut rng, &FakeClock, &files)
        .restore(RestoreRequest {
            trust_config: "docs/trust.json".into(),
            input: "/external/owner.backup.json".into(),
            replace_active_trust: None,
            replace_active_key_id: None,
        });
    let Err(wrong) = wrong else {
        panic!("wrong passphrase must fail");
    };
    let mut tampered = files
        .bounded_nofollow_read("/external/owner.backup.json")
        .expect("backup bytes");
    let marker = b"\"ciphertext\":\"";
    let position = tampered
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("ciphertext")
        + marker.len();
    tampered[position] = if tampered[position] == b'a' {
        b'b'
    } else {
        b'a'
    };
    files
        .bytes
        .lock()
        .expect("bytes")
        .insert("/external/owner.backup.json".into(), tampered);
    let tamper_tty = HiddenTty::new(&[b"correct horse"]);
    let mut rng = FakeRng;
    let tamper =
        AuthorityCommandRunner::new(&store, &(), &tamper_tty, &mut rng, &FakeClock, &files)
            .restore(RestoreRequest {
                trust_config: "docs/trust.json".into(),
                input: "/external/owner.backup.json".into(),
                replace_active_trust: None,
                replace_active_key_id: None,
            });
    let Err(tamper) = tamper else {
        panic!("tamper must fail");
    };
    assert_eq!(wrong.to_string(), "BACKUP_TAMPERED_OR_WRONG_PASSPHRASE");
    assert_eq!(tamper.to_string(), wrong.to_string());
    assert_eq!(store.state.lock().expect("state").restores, 0);
}

#[test]
fn overwrite_restore_requires_the_exact_current_trust_and_key() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    let backup_tty = HiddenTty::new(&[b"correct horse", b"correct horse"]);
    let mut rng = FakeRng;
    AuthorityCommandRunner::new(&store, &(), &backup_tty, &mut rng, &FakeClock, &files)
        .backup(BackupRequest {
            trust_config: "docs/trust.json".into(),
            output: "/external/owner.backup.json".into(),
        })
        .expect("backup");
    let current = store
        .read_active_ref("gocode")
        .expect("active")
        .expect("active key");
    let key_id = runne_project_owner_authority::key_id(&current.public_key());
    let reject_tty = HiddenTty::new(&[]);
    let mut rng = FakeRng;
    assert!(
        AuthorityCommandRunner::new(&store, &(), &reject_tty, &mut rng, &FakeClock, &files)
            .restore(RestoreRequest {
                trust_config: "docs/trust.json".into(),
                input: "/external/owner.backup.json".into(),
                replace_active_trust: Some("docs/trust.json".into()),
                replace_active_key_id: Some([0; 32]),
            })
            .is_err()
    );
    assert_eq!(store.state.lock().expect("state").restores, 0);
    let accept_tty = HiddenTty::new(&[b"correct horse"]);
    let mut rng = FakeRng;
    AuthorityCommandRunner::new(&store, &(), &accept_tty, &mut rng, &FakeClock, &files)
        .restore(RestoreRequest {
            trust_config: "docs/trust.json".into(),
            input: "/external/owner.backup.json".into(),
            replace_active_trust: Some("docs/trust.json".into()),
            replace_active_key_id: Some(key_id),
        })
        .expect("exact overwrite");
    assert_eq!(store.state.lock().expect("state").restores, 1);
}

#[test]
fn restore_rejects_missing_anchor_before_secret_input_or_store_mutation() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    store.state.lock().expect("state").floor = None;
    let tty = HiddenTty::new(&[b"correct horse"]);
    let mut rng = FakeRng;

    assert!(
        AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
            .restore(RestoreRequest {
                trust_config: "docs/trust.json".into(),
                input: "/external/owner.backup.json".into(),
                replace_active_trust: None,
                replace_active_key_id: None,
            })
            .is_err()
    );
    assert_eq!(tty.entries.lock().expect("entries").len(), 1);
    assert_eq!(store.state.lock().expect("state").restores, 0);
}
