#![cfg(feature = "test-support")]

use gocode_local_store::{
    BoundedCanonicalId, LocalStore, MutationIdentity, MutationOperation, MutationTargetKind,
    SecurityStateError, security_open_test_support::install_admitted_open_hooks,
};
use gocode_secure_store::{
    SecureStore, StoredSecurityAnchor, test_support::DeterministicSecureStore,
};

fn snapshot(path: &std::path::Path) -> (i64, i64) {
    let connection = rusqlite::Connection::open(path).expect("snapshot database");
    let generation = connection
        .query_row(
            "SELECT db_generation FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .expect("generation");
    let rows = connection
        .query_row("SELECT COUNT(*) FROM mutation_ledger", [], |row| row.get(0))
        .expect("ledger rows");
    (generation, rows)
}

fn anchor(secure: &DeterministicSecureStore, profile: [u8; 32]) -> StoredSecurityAnchor {
    let lock = secure.acquire_security_profile_lock(profile).expect("lock");
    secure.read_security_anchor(&lock).expect("anchor")
}

#[test]
fn admission_rejects_a_sqlite_handle_detached_by_path_swap() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [91; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    drop(LocalStore::open_anchored(&path, &secure, profile).expect("genesis"));
    let replacement = directory.path().join("replacement.sqlite3");
    std::fs::copy(&path, &replacement).expect("clone");
    let before_a = snapshot(&path);
    let before_b = snapshot(&replacement);
    let before_anchor = anchor(&secure, profile);
    let staged = directory.path().join("staged.sqlite3");
    let before_path = path.clone();
    let before_replacement = replacement.clone();
    let before_staged = staged.clone();
    let after_path = path.clone();
    let after_replacement = replacement.clone();
    install_admitted_open_hooks(
        move || {
            std::fs::rename(&before_path, &before_staged).expect("stage original");
            std::fs::rename(&before_replacement, &before_path).expect("install clone");
        },
        move || {
            std::fs::rename(&after_path, &after_replacement).expect("remove clone");
            std::fs::rename(&staged, &after_path).expect("restore original");
        },
    );
    assert!(matches!(
        LocalStore::open_anchored(&path, &secure, profile),
        Err(SecurityStateError::AdmissionFailed)
    ));
    assert_eq!(snapshot(&path), before_a);
    assert_eq!(snapshot(&replacement), before_b);
    assert_eq!(anchor(&secure, profile), before_anchor);
    assert!(LocalStore::open_anchored(&path, &secure, profile).is_ok());
}

#[test]
fn admitted_store_rejects_path_replacement_before_prepare() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [92; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    drop(LocalStore::open_anchored(&path, &secure, profile).expect("genesis"));
    let replacement = directory.path().join("replacement.sqlite3");
    std::fs::copy(&path, &replacement).expect("clone");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let detached = directory.path().join("detached.sqlite3");
    let before_a = snapshot(&path);
    let before_b = snapshot(&replacement);
    let before_anchor = anchor(&secure, profile);
    std::fs::rename(&path, &detached).expect("detach A");
    std::fs::rename(&replacement, &path).expect("install B");
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::WorkspaceOpen,
        MutationTargetKind::Workspace,
        BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000092").expect("id"),
        "replace",
        0,
        [3; 32],
    )
    .expect("identity");
    assert!(matches!(
        store.prepare_anchored_mutation(&secure, identity),
        Err(SecurityStateError::AdmissionFailed)
    ));
    assert_eq!(snapshot(&detached), before_a);
    assert_eq!(snapshot(&path), before_b);
    assert_eq!(anchor(&secure, profile), before_anchor);
}

#[test]
fn legacy_prepare_checks_admission_before_rejecting_v7_evidence() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [93; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    drop(LocalStore::open_anchored(&path, &secure, profile).expect("genesis"));
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let before = snapshot(&path);
    let before_anchor = anchor(&secure, profile);
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::WorkspaceOpen,
        MutationTargetKind::Workspace,
        BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000093").expect("id"),
        "legacy-order",
        1,
        [3; 32],
    )
    .expect("identity");
    assert!(matches!(
        store.prepare_anchored_mutation(&secure, identity.clone()),
        Err(SecurityStateError::InvalidTransition)
    ));
    assert_eq!(snapshot(&path), before);
    assert_eq!(anchor(&secure, profile), before_anchor);
    let replacement = directory.path().join("replacement.sqlite3");
    std::fs::copy(&path, &replacement).expect("clone");
    let detached = directory.path().join("detached.sqlite3");
    std::fs::rename(&path, &detached).expect("detach");
    std::fs::rename(&replacement, &path).expect("replace");
    assert!(matches!(
        store.prepare_anchored_mutation(&secure, identity),
        Err(SecurityStateError::AdmissionFailed)
    ));
}
