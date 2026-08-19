use super::super::tests::{FakeClock, FakeRng, FakeStore};
use super::super::{AuthorityCommandRunner, RestoreRequest};
use super::{HiddenTty, fixture_files, initialized};

#[test]
fn restore_rejects_backup_inside_repository_before_tty_or_store() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    files
        .bytes
        .lock()
        .expect("bytes")
        .insert("repo/owner.backup.json".into(), b"{}\n".to_vec());
    let tty = HiddenTty::new(&[b"correct horse"]);
    let mut rng = FakeRng;

    assert!(
        AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
            .restore(RestoreRequest {
                trust_config: "docs/trust.json".into(),
                input: "repo/owner.backup.json".into(),
                replace_active_trust: None,
                replace_active_key_id: None,
            })
            .is_err()
    );
    assert_eq!(tty.entries.lock().expect("entries").len(), 1);
    assert_eq!(store.state.lock().expect("state").restores, 0);
}

#[test]
fn restore_requires_both_replacement_arguments() {
    let store = FakeStore::new();
    let files = fixture_files();
    initialized(&store, &files);
    let tty = HiddenTty::new(&[]);
    let mut rng = FakeRng;

    assert!(
        AuthorityCommandRunner::new(&store, &(), &tty, &mut rng, &FakeClock, &files)
            .restore(RestoreRequest {
                trust_config: "docs/trust.json".into(),
                input: "/external/owner.backup.json".into(),
                replace_active_trust: Some("docs/trust.json".into()),
                replace_active_key_id: None,
            })
            .is_err()
    );
    assert_eq!(store.state.lock().expect("state").restores, 0);
}
