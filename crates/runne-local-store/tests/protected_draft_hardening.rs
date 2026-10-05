#![cfg(all(feature = "test-support", target_os = "linux"))]

use std::sync::{Arc, mpsc};
use std::time::Duration;

use runne_local_store::{LocalStore, ProtectedDraftError, ProtectedDraftScope};
use runne_secure_store::test_support::DeterministicSecureStore;
use rusqlite::Connection;

const PROFILE: [u8; 32] = [0x61; 32];
const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000201";

fn scope(workspace: u32) -> ProtectedDraftScope {
    ProtectedDraftScope {
        lineage: "lineage-a".into(),
        authority: "authority-a".into(),
        principal: "principal-a".into(),
        project_id: PROJECT.into(),
        workspace_id: format!("018f2e3a-7000-7000-8000-{workspace:012x}"),
    }
}

fn open(path: &std::path::Path, secure: &DeterministicSecureStore) -> LocalStore {
    LocalStore::open_anchored(path, secure, PROFILE).expect("anchored profile")
}

fn sidecar(path: &std::path::Path) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(".drafts.sqlite3");
    value.into()
}

#[test]
fn schema_injection_is_rejected_before_a_save_can_report_success() {
    for (index, object) in [
        "CREATE TRIGGER erase_after_insert AFTER INSERT ON protected_drafts BEGIN DELETE FROM protected_drafts; END",
        "CREATE VIEW injected AS SELECT * FROM protected_drafts",
        "CREATE INDEX injected_index ON protected_drafts(revision)",
    ]
    .into_iter()
    .enumerate()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("profile-{index}.sqlite3"));
        let secure = DeterministicSecureStore::new(PROFILE);
        let store = open(&path, &secure);
        let draft_scope = scope(201 + u32::try_from(index).expect("three schema cases"));
        let token = store.load_protected_draft(&secure, &draft_scope).unwrap().scope_token;
        Connection::open(sidecar(&path)).unwrap().execute_batch(object).unwrap();
        assert!(matches!(
            store.save_protected_draft(&secure, &draft_scope, &token, 0, "private"),
            Err(ProtectedDraftError::Invalid)
        ));
    }
}

#[test]
fn interrupted_nonatomic_schema_and_unsafe_auxiliaries_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let store = open(&path, &secure);
    let draft_scope = scope(202);
    store.load_protected_draft(&secure, &draft_scope).unwrap();
    let sidecar_path = sidecar(&path);
    Connection::open(&sidecar_path)
        .unwrap()
        .pragma_update(None, "user_version", 0)
        .unwrap();
    assert!(matches!(
        store.load_protected_draft(&secure, &draft_scope),
        Err(ProtectedDraftError::Invalid)
    ));
    Connection::open(&sidecar_path)
        .unwrap()
        .pragma_update(None, "user_version", 2)
        .unwrap();
    let wal = format!("{}-wal", sidecar_path.display());
    std::os::unix::fs::symlink(directory.path().join("foreign"), &wal).unwrap();
    assert!(matches!(
        store.load_protected_draft(&secure, &draft_scope),
        Err(ProtectedDraftError::Unavailable)
    ));
}

#[test]
fn sidecar_hardlink_and_nonowner_directory_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let store = open(&path, &secure);
    let draft_scope = scope(203);
    let token = store
        .load_protected_draft(&secure, &draft_scope)
        .unwrap()
        .scope_token;
    store
        .save_protected_draft(&secure, &draft_scope, &token, 0, "private")
        .unwrap();
    let alias = directory.path().join("alias.sqlite3");
    std::fs::hard_link(sidecar(&path), &alias).unwrap();
    assert!(matches!(
        store.load_protected_draft(&secure, &draft_scope),
        Err(ProtectedDraftError::Unavailable)
    ));
    std::fs::remove_file(alias).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            store.load_protected_draft(&secure, &draft_scope),
            Err(ProtectedDraftError::Unavailable)
        ));
    }
}

#[test]
fn independent_connections_initialize_once_and_compare_and_swap() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let secure = Arc::new(DeterministicSecureStore::new(PROFILE));
    drop(LocalStore::open_anchored(&path, secure.as_ref(), PROFILE).unwrap());
    let store_a = open(&path, secure.as_ref());
    let store_b = open(&path, secure.as_ref());
    let (ready_a_tx, ready_a_rx) = mpsc::channel();
    let (ready_b_tx, ready_b_rx) = mpsc::channel();
    let (go_a_tx, go_a_rx) = mpsc::channel();
    let (go_b_tx, go_b_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    std::thread::scope(|scope_threads| {
        let secure_a = Arc::clone(&secure);
        let result_a = result_tx.clone();
        scope_threads.spawn(move || {
            ready_a_tx.send(()).unwrap();
            go_a_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let loaded = store_a.load_protected_draft(secure_a.as_ref(), &scope(204));
            let _ = result_a.send(loaded.map(|draft| draft.revision));
        });
        let secure_b = Arc::clone(&secure);
        scope_threads.spawn(move || {
            ready_b_tx.send(()).unwrap();
            go_b_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let loaded = store_b.load_protected_draft(secure_b.as_ref(), &scope(204));
            let _ = result_tx.send(loaded.map(|draft| draft.revision));
        });
        ready_a_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        ready_b_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        go_a_tx.send(()).unwrap();
        go_b_tx.send(()).unwrap();
        let first = result_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let second = result_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(first.unwrap(), 0);
        assert_eq!(second.unwrap(), 0);
    });
    let store_a = open(&path, secure.as_ref());
    let store_b = open(&path, secure.as_ref());
    let draft_scope = scope(204);
    let token = store_a
        .load_protected_draft(secure.as_ref(), &draft_scope)
        .unwrap()
        .scope_token;
    let (ready_a_tx, ready_a_rx) = mpsc::channel();
    let (ready_b_tx, ready_b_rx) = mpsc::channel();
    let (go_a_tx, go_a_rx) = mpsc::channel();
    let (go_b_tx, go_b_rx) = mpsc::channel();
    std::thread::scope(|scope_threads| {
        let secure_a = Arc::clone(&secure);
        let scope_a = draft_scope.clone();
        let token_a = token.clone();
        let first = scope_threads.spawn(move || {
            ready_a_tx.send(()).unwrap();
            go_a_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            store_a.save_protected_draft(secure_a.as_ref(), &scope_a, &token_a, 0, "first")
        });
        let secure_b = Arc::clone(&secure);
        let scope_b = draft_scope.clone();
        let token_b = token.clone();
        let second = scope_threads.spawn(move || {
            ready_b_tx.send(()).unwrap();
            go_b_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            store_b.save_protected_draft(secure_b.as_ref(), &scope_b, &token_b, 0, "second")
        });
        ready_a_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        ready_b_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        go_a_tx.send(()).unwrap();
        go_b_tx.send(()).unwrap();
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Err(ProtectedDraftError::Conflict)))
                .count(),
            1
        );
    });
    let version: i64 = Connection::open(sidecar(&path))
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 2);
}

#[test]
fn lifetime_capacity_counts_tombstones_and_rejects_unsafe_revision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let store = open(&path, &secure);
    let mut first = None;
    for index in 0..128 {
        let draft_scope = scope(300 + index);
        let token = store
            .load_protected_draft(&secure, &draft_scope)
            .unwrap()
            .scope_token;
        let saved = store
            .save_protected_draft(&secure, &draft_scope, &token, 0, "draft")
            .unwrap();
        if index == 0 {
            first = Some((draft_scope, token, saved));
        }
    }
    let (first_scope, first_token, first_saved) = first.unwrap();
    let cleared = store
        .clear_protected_draft(&secure, &first_scope, &first_token, first_saved.revision)
        .unwrap();
    let overflow = scope(500);
    let overflow_token = store
        .load_protected_draft(&secure, &overflow)
        .unwrap()
        .scope_token;
    assert!(matches!(
        store.save_protected_draft(&secure, &overflow, &overflow_token, 0, "draft"),
        Err(ProtectedDraftError::Capacity)
    ));
    let connection = Connection::open(sidecar(&path)).unwrap();
    connection
        .execute(
            "UPDATE protected_drafts SET revision=?1 WHERE workspace_id=?2",
            rusqlite::params![9_007_199_254_740_992i64, first_scope.workspace_id],
        )
        .unwrap();
    assert!(matches!(
        store.load_protected_draft(&secure, &first_scope),
        Err(ProtectedDraftError::Invalid)
    ));
    assert!(matches!(
        store.clear_protected_draft(&secure, &first_scope, &first_token, 9_007_199_254_740_992),
        Err(ProtectedDraftError::Invalid)
    ));
    assert_eq!(cleared.revision, 2);
}
