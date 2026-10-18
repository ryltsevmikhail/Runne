#[path = "project_trust_sidecar_v3/support.rs"]
mod support;

use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus,
};
use runne_store::ProjectTrustStore;
use support::*;

#[test]
fn strict_v2_migration_preserves_identity_records_and_backfills_allow() {
    let root = tempfile::tempdir().unwrap();
    let canonical = canonical_path(root.path(), "legacy.sqlite");
    create_v2(&canonical, 9123);

    let store = ProjectTrustStore::open(&canonical, AUTHORITY).unwrap();
    assert_eq!(store.instance_epoch().unwrap(), 9123);
    for (project, status, mask, revision) in [
        (TRUSTED_PROJECT, ProjectTrustStatus::Trusted, 8, 12),
        (MANAGED_PROJECT, ProjectTrustStatus::Managed, 127, 37),
        (UNTRUSTED_PROJECT, ProjectTrustStatus::Untrusted, 1, 4),
    ] {
        let record = store
            .load(ProjectTrustProjectId::from_bytes(project))
            .unwrap();
        assert_eq!(
            (record.status, record.managed_deny_mask, record.revision),
            (status, mask, revision)
        );
        let lease = store
            .acquire_effect_lease(ProjectTrustProjectId::from_bytes(project))
            .unwrap();
        let snapshot = lease.snapshot().unwrap();
        assert_eq!(snapshot.record, record);
        assert!(snapshot.policy.is_all_allow());
    }
}

#[test]
fn v2_catalog_tampering_is_rejected_without_migration() {
    let root = tempfile::tempdir().unwrap();
    let canonical = canonical_path(root.path(), "tampered.sqlite");
    create_v2(&canonical, 8);
    rusqlite::Connection::open(sidecar_path(&canonical))
        .unwrap()
        .execute(
            "ALTER TABLE project_trust ADD COLUMN unexpected INTEGER",
            [],
        )
        .unwrap();

    assert!(ProjectTrustStore::open(&canonical, AUTHORITY).is_err());
    let connection = rusqlite::Connection::open(sidecar_path(&canonical)).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT schema_version FROM project_trust_schema",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}

#[test]
fn unknown_v2_schema_marker_is_rejected_without_catalog_rewrite() {
    let root = tempfile::tempdir().unwrap();
    let canonical = canonical_path(root.path(), "unknown.sqlite");
    create_v2(&canonical, 9);
    rusqlite::Connection::open(sidecar_path(&canonical))
        .unwrap()
        .pragma_update(None, "user_version", 77)
        .unwrap();

    assert!(ProjectTrustStore::open(&canonical, AUTHORITY).is_err());
    assert_eq!(
        rusqlite::Connection::open(sidecar_path(&canonical))
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        77
    );
}

#[test]
fn unknown_legacy_mask_is_rejected_before_v2_migration() {
    let root = tempfile::tempdir().unwrap();
    let canonical = canonical_path(root.path(), "unknown-mask.sqlite");
    create_v2(&canonical, 10);
    let connection = rusqlite::Connection::open(sidecar_path(&canonical)).unwrap();
    connection
        .pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    connection
        .execute(
            "UPDATE project_trust SET managed_deny_mask=128 WHERE project_id=?1",
            [&TRUSTED_PROJECT[..]],
        )
        .unwrap();

    assert!(ProjectTrustStore::open(&canonical, AUTHORITY).is_err());
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT schema_version FROM project_trust_schema",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}

#[test]
fn v2_authority_mismatch_is_rejected_before_migration() {
    let root = tempfile::tempdir().unwrap();
    let canonical = canonical_path(root.path(), "foreign-authority.sqlite");
    create_v2(&canonical, 11);
    rusqlite::Connection::open(sidecar_path(&canonical))
        .unwrap()
        .execute(
            "UPDATE project_trust_schema SET authority_id=?1 WHERE id=1",
            [&[0x99_u8; 16][..]],
        )
        .unwrap();

    assert!(ProjectTrustStore::open(&canonical, AUTHORITY).is_err());
    let connection = rusqlite::Connection::open(sidecar_path(&canonical)).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT schema_version FROM project_trust_schema",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
        2
    );
}
