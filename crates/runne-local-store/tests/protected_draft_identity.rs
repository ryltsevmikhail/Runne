#![cfg(all(feature = "test-support", target_os = "linux"))]

use runne_local_store::{LocalStore, ProtectedDraftError, ProtectedDraftScope};
use runne_secure_store::test_support::DeterministicSecureStore;
use rusqlite::Connection;

const PROFILE: [u8; 32] = [0x81; 32];
const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000301";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000302";

fn scope() -> ProtectedDraftScope {
    ProtectedDraftScope {
        lineage: "lineage-a".into(),
        authority: "authority-a".into(),
        principal: "principal-a".into(),
        project_id: PROJECT.into(),
        workspace_id: WORKSPACE.into(),
    }
}

fn open(
    path: &std::path::Path,
    secure: &DeterministicSecureStore,
    profile: [u8; 32],
) -> LocalStore {
    LocalStore::open_anchored(path, secure, profile).unwrap()
}

fn sidecar(path: &std::path::Path) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(".drafts.sqlite3");
    value.into()
}

#[test]
fn every_runtime_scope_field_is_authenticated_as_aad() {
    let scope_changes = [
        ("lineage", "lineage-b", "lineage"),
        ("authority", "authority-b", "authority"),
        ("principal", "principal-b", "principal"),
        (
            "project_id",
            "018f2e3a-7000-7000-8000-000000000303",
            "project_id",
        ),
        (
            "workspace_id",
            "018f2e3a-7000-7000-8000-000000000304",
            "workspace_id",
        ),
    ];
    for (index, (column, value, field)) in scope_changes.into_iter().enumerate() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.sqlite3");
        let secure = DeterministicSecureStore::new(PROFILE);
        let store = open(&path, &secure, PROFILE);
        let original = scope();
        let token = store
            .load_protected_draft(&secure, &original)
            .unwrap()
            .scope_token;
        store
            .save_protected_draft(&secure, &original, &token, 0, "authenticated scope")
            .unwrap();
        let mut altered = original.clone();
        match field {
            "lineage" => altered.lineage = value.into(),
            "authority" => altered.authority = value.into(),
            "principal" => altered.principal = value.into(),
            "project_id" => altered.project_id = value.into(),
            "workspace_id" => altered.workspace_id = value.into(),
            _ => unreachable!(),
        }
        Connection::open(sidecar(&path))
            .unwrap()
            .execute(&format!("UPDATE protected_drafts SET {column}=?1"), [value])
            .unwrap();
        assert!(
            matches!(
                store.load_protected_draft(&secure, &altered),
                Err(ProtectedDraftError::Invalid)
            ),
            "scope field index {index}"
        );
    }
}

#[test]
fn foreign_profile_and_database_sidecar_transplants_fail_authentication() {
    for (index, profile) in [[0x82; 32], PROFILE].into_iter().enumerate() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.sqlite3");
        let target_path = directory.path().join("target.sqlite3");
        let source_secure = DeterministicSecureStore::new(PROFILE);
        let source = open(&source_path, &source_secure, PROFILE);
        let source_scope = scope();
        let source_token = source
            .load_protected_draft(&source_secure, &source_scope)
            .unwrap()
            .scope_token;
        source
            .save_protected_draft(
                &source_secure,
                &source_scope,
                &source_token,
                0,
                "transplanted",
            )
            .unwrap();
        drop(source);
        let target_secure = DeterministicSecureStore::new(profile);
        let target = open(&target_path, &target_secure, profile);
        let target_token = target
            .load_protected_draft(&target_secure, &source_scope)
            .unwrap()
            .scope_token;
        assert_ne!(source_token, target_token);
        std::fs::copy(sidecar(&source_path), sidecar(&target_path)).unwrap();
        assert!(
            matches!(
                target.load_protected_draft(&target_secure, &source_scope),
                Err(ProtectedDraftError::Invalid)
            ),
            "transplant case {index}"
        );
    }
}

#[test]
fn revision_and_deleted_metadata_tampering_fail_closed() {
    for (column, value) in [("revision", 2i64), ("deleted", 1i64)] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.sqlite3");
        let secure = DeterministicSecureStore::new(PROFILE);
        let store = open(&path, &secure, PROFILE);
        let draft_scope = scope();
        let token = store
            .load_protected_draft(&secure, &draft_scope)
            .unwrap()
            .scope_token;
        store
            .save_protected_draft(&secure, &draft_scope, &token, 0, "metadata protected")
            .unwrap();
        Connection::open(sidecar(&path))
            .unwrap()
            .execute(&format!("UPDATE protected_drafts SET {column}=?1"), [value])
            .unwrap();
        assert!(
            store.load_protected_draft(&secure, &draft_scope).is_err(),
            "{column} tamper"
        );
    }
}
