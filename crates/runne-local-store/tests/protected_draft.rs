#![cfg(all(feature = "test-support", target_os = "linux"))]

use runne_local_store::{LocalStore, ProtectedDraftError, ProtectedDraftScope};
use runne_secure_store::test_support::DeterministicSecureStore;
use rusqlite::Connection;

const PROFILE: [u8; 32] = [0x71; 32];
const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000101";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000102";

fn scope() -> ProtectedDraftScope {
    ProtectedDraftScope {
        lineage: "test-lineage".into(),
        authority: "test-authority".into(),
        principal: "test-principal".into(),
        project_id: PROJECT.into(),
        workspace_id: WORKSPACE.into(),
    }
}

fn open(path: &std::path::Path, secure: &DeterministicSecureStore) -> LocalStore {
    LocalStore::open_anchored(path, secure, PROFILE).expect("anchored profile")
}

#[test]
#[allow(clippy::too_many_lines)]
fn protected_draft_reopens_encrypted_and_rejects_scope_or_ciphertext_changes() {
    let directory = tempfile::tempdir().unwrap();
    let profile_path = directory.path().join("profile.sqlite3");
    let sidecar = directory.path().join("profile.sqlite3.drafts.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let prompt = "draft canary: приватный текст";
    let store = open(&profile_path, &secure);
    let scope = scope();
    let token = store
        .load_protected_draft(&secure, &scope)
        .unwrap()
        .scope_token;
    let saved = store
        .save_protected_draft(&secure, &scope, &token, 0, prompt)
        .unwrap();
    assert_eq!(saved.revision, 1);
    drop(open(&profile_path, &secure));
    let bytes = std::fs::read(&sidecar).unwrap();
    assert!(
        !bytes
            .windows(prompt.len())
            .any(|window| window == prompt.as_bytes())
    );
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut auxiliary = sidecar.as_os_str().to_owned();
        auxiliary.push(suffix);
        let auxiliary = std::path::PathBuf::from(auxiliary);
        if auxiliary.exists() {
            let contents = std::fs::read(auxiliary).unwrap();
            assert!(
                !contents
                    .windows(prompt.len())
                    .any(|window| window == prompt.as_bytes())
            );
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let reloaded = open(&profile_path, &secure)
        .load_protected_draft(&secure, &scope)
        .unwrap();
    assert_eq!(reloaded.revision, 1);
    assert_eq!(reloaded.prompt.as_deref(), Some(prompt));
    assert_eq!(reloaded.scope_token, token);
    let other = ProtectedDraftScope {
        principal: "other-principal".into(),
        ..scope.clone()
    };
    assert_eq!(
        open(&profile_path, &secure)
            .load_protected_draft(&secure, &other)
            .unwrap()
            .prompt,
        None
    );
    let transplanted = ProtectedDraftScope {
        workspace_id: "018f2e3a-7000-7000-8000-000000000103".into(),
        ..scope.clone()
    };
    Connection::open(&sidecar)
        .unwrap()
        .execute(
            "INSERT INTO protected_drafts(lineage,authority,principal,project_id,workspace_id,revision,deleted,payload) SELECT lineage,authority,principal,project_id,?1,revision,deleted,payload FROM protected_drafts",
            [transplanted.workspace_id.as_str()],
        )
        .unwrap();
    assert!(matches!(
        open(&profile_path, &secure).load_protected_draft(&secure, &transplanted),
        Err(ProtectedDraftError::Invalid)
    ));

    let mut tampered: Vec<u8> = Connection::open(&sidecar)
        .unwrap()
        .query_row(
            "SELECT payload FROM protected_drafts WHERE workspace_id=?1",
            [WORKSPACE],
            |row| row.get(0),
        )
        .unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    Connection::open(&sidecar)
        .unwrap()
        .execute(
            "UPDATE protected_drafts SET payload=?1 WHERE workspace_id=?2",
            rusqlite::params![tampered, WORKSPACE],
        )
        .unwrap();
    assert!(matches!(
        open(&profile_path, &secure).load_protected_draft(&secure, &scope),
        Err(ProtectedDraftError::Invalid)
    ));
    assert!(matches!(
        open(&profile_path, &secure).save_protected_draft(
            &secure,
            &scope,
            &token,
            1,
            "replacement"
        ),
        Err(ProtectedDraftError::Invalid)
    ));
}

#[test]
fn protected_draft_rejects_unavailable_key_symlink_and_profile_token_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let sidecar = directory.path().join("profile.sqlite3.drafts.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let store = open(&path, &secure);
    let scope = scope();
    let token = store
        .load_protected_draft(&secure, &scope)
        .unwrap()
        .scope_token;
    store
        .save_protected_draft(&secure, &scope, &token, 0, "private")
        .unwrap();
    std::fs::remove_file(&sidecar).unwrap();
    std::os::unix::fs::symlink(directory.path().join("target"), &sidecar).unwrap();
    assert!(matches!(
        store.load_protected_draft(&secure, &scope),
        Err(ProtectedDraftError::Unavailable)
    ));
    std::fs::remove_file(&sidecar).unwrap();
    secure.disable_mutation_payload_encryption();
    assert!(matches!(
        store.load_protected_draft(&secure, &scope),
        Err(ProtectedDraftError::Unavailable)
    ));

    let profile_b = [0x72; 32];
    let secure_b = DeterministicSecureStore::new(profile_b);
    let other_path = directory.path().join("other-profile.sqlite3");
    let other_store = LocalStore::open_anchored(&other_path, &secure_b, profile_b).unwrap();
    let other_token = other_store
        .load_protected_draft(&secure_b, &scope)
        .unwrap()
        .scope_token;
    assert_ne!(token, other_token);
}

#[test]
fn protected_draft_compare_and_swap_and_retry_safe_tombstone() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let store = open(&path, &secure);
    let scope = scope();
    let token = store
        .load_protected_draft(&secure, &scope)
        .unwrap()
        .scope_token;
    let first = store
        .save_protected_draft(&secure, &scope, &token, 0, "first")
        .unwrap();
    let second = store
        .save_protected_draft(&secure, &scope, &token, first.revision, "newer")
        .unwrap();
    assert!(matches!(
        store.save_protected_draft(&secure, &scope, &token, first.revision, "stale"),
        Err(ProtectedDraftError::Conflict)
    ));
    assert!(matches!(
        store.clear_protected_draft(&secure, &scope, &token, first.revision),
        Err(ProtectedDraftError::Conflict)
    ));
    let cleared = store
        .clear_protected_draft(&secure, &scope, &token, second.revision)
        .unwrap();
    assert_eq!(cleared.revision, second.revision + 1);
    assert_eq!(cleared.prompt, None);
    let repeated = store
        .clear_protected_draft(&secure, &scope, &token, second.revision)
        .unwrap();
    assert_eq!(repeated.revision, cleared.revision);
    assert_eq!(repeated.prompt, cleared.prompt);
    assert_eq!(repeated.scope_token, cleared.scope_token);
    let reloaded = store.load_protected_draft(&secure, &scope).unwrap();
    assert_eq!(reloaded.revision, cleared.revision);
    assert_eq!(reloaded.prompt, cleared.prompt);
    let after_clear = store
        .save_protected_draft(&secure, &scope, &token, cleared.revision, "after clear")
        .unwrap();
    assert_eq!(after_clear.revision, cleared.revision + 1);
}

#[test]
fn protected_draft_utf8_limit_is_measured_in_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let store = open(&path, &secure);
    let scope = scope();
    let token = store
        .load_protected_draft(&secure, &scope)
        .unwrap()
        .scope_token;
    let fitting = "é".repeat(32 * 1024);
    assert_eq!(
        store
            .save_protected_draft(&secure, &scope, &token, 0, &fitting)
            .unwrap()
            .revision,
        1
    );
    assert!(matches!(
        store.save_protected_draft(&secure, &scope, &token, 1, &format!("{fitting}é")),
        Err(ProtectedDraftError::Invalid)
    ));
}
