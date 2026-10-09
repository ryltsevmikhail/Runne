use rusqlite::Connection;
use std::path::{Path, PathBuf};

pub const AUTHORITY: [u8; 16] = [0x4a; 16];
pub const TRUSTED_PROJECT: [u8; 16] = [0x71; 16];
pub const MANAGED_PROJECT: [u8; 16] = [0x72; 16];
pub const UNTRUSTED_PROJECT: [u8; 16] = [0x73; 16];

const IDENTITY_V2_SQL: &str = "CREATE TABLE project_trust_schema (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    schema_kind TEXT NOT NULL CHECK(schema_kind = 'runne.project-trust'),
    schema_version INTEGER NOT NULL CHECK(schema_version = 2),
    instance_epoch INTEGER NOT NULL CHECK(instance_epoch > 0),
    authority_id BLOB NOT NULL CHECK(length(authority_id) = 16)
)";

const TRUST_V2_SQL: &str = "CREATE TABLE project_trust (
    project_id BLOB PRIMARY KEY CHECK(length(project_id) = 16),
    status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 3),
    managed_deny_mask INTEGER NOT NULL CHECK(managed_deny_mask >= 0),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    updated_at INTEGER NOT NULL
)";

pub fn canonical_path(root: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let runtime = root.join("runtime");
    let daemon = runtime.join("daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    daemon.join(name)
}

pub fn sidecar_path(canonical: &Path) -> PathBuf {
    PathBuf::from(format!("{}.project-trust", canonical.display()))
}

pub fn create_v2(canonical: &Path, epoch: i64) {
    use std::os::unix::fs::PermissionsExt as _;

    let sidecar = sidecar_path(canonical);
    let connection = Connection::open(&sidecar).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
            .unwrap(),
        "delete"
    );
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    connection
        .execute_batch(&format!(
            "{IDENTITY_V2_SQL};{TRUST_V2_SQL};PRAGMA user_version = 2;"
        ))
        .unwrap();
    connection
        .execute(
            "INSERT INTO project_trust_schema VALUES (1, 'runne.project-trust', 2, ?1, ?2)",
            rusqlite::params![epoch, AUTHORITY.as_slice()],
        )
        .unwrap();
    for (project, status, mask, revision) in [
        (TRUSTED_PROJECT, 2, 8, 12),
        (MANAGED_PROJECT, 3, 127, 37),
        (UNTRUSTED_PROJECT, 1, 1, 4),
    ] {
        connection
            .execute(
                "INSERT INTO project_trust VALUES (?1, ?2, ?3, ?4, 123)",
                rusqlite::params![project.as_slice(), status, mask, revision],
            )
            .unwrap();
    }
    drop(connection);
    std::fs::set_permissions(sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
}
