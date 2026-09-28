use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use super::{material_representations, nm10_rules, secret_scan};

/// Binds one real session-bus fixture socket inside the owner-private fixture
/// root and returns its strictly valid socket path.
///
/// The listener is dropped immediately: the socket file survives (absolute
/// path, socket type, own-euid ownership), while connections to it are
/// refused instantly — the exact fast-fail a host without a session bus
/// produces, so Linux provider-bound launches do not depend on a real bus.
/// `with_validated_session_bus_address` re-validates the path through the
/// strict production checks before injecting it into the launch spec.
pub(super) fn fixture_session_bus(root: &Path, name: &str) -> PathBuf {
    let socket_path = root.join(name);
    let listener = UnixListener::bind(&socket_path).expect("fixture session bus socket");
    drop(listener);
    socket_path
}

pub(super) fn frozen_registered_canaries() -> Vec<String> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/golden/t1/fake-canary-secrets-v1.json"
    )))
    .expect("frozen canary fixture");
    ["FAKE-SECRET-003", "FAKE-SECRET-006"]
        .into_iter()
        .map(|id| {
            fixture["canaries"]
                .as_array()
                .expect("canary list")
                .iter()
                .find(|canary| canary["id"] == id)
                .expect("registered synthetic secret")["value"]
                .as_str()
                .expect("canary value")
                .to_owned()
        })
        .collect()
}

pub(super) fn seed_hostile_workspace(root: &Path) {
    for dir in [
        "instructions",
        "skills",
        "hooks",
        "helpers",
        "notes",
        ".aws",
        ".ssh",
    ] {
        std::fs::create_dir_all(root.join(dir)).expect("hostile project directories");
    }

    let secrets: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/golden/t1/fake-canary-secrets-v1.json"
    )))
    .expect("frozen fake-secret fixture");
    let secret = |id: &str| {
        secrets["canaries"]
            .as_array()
            .expect("frozen secret list")
            .iter()
            .find(|item| item["id"] == id)
            .expect("frozen secret id")["value"]
            .as_str()
            .expect("frozen secret value")
    };
    for (path, entries) in [
        (
            ".env",
            vec![("TOKEN", "FAKE-SECRET-003"), ("CRASH", "FAKE-SECRET-006")],
        ),
        (
            ".aws/config",
            vec![("KEY", "FAKE-SECRET-001"), ("BEARER", "FAKE-SECRET-002")],
        ),
        (".npmrc", vec![("HEADER", "FAKE-SECRET-004")]),
        (".netrc", vec![("BLOB", "FAKE-SECRET-005")]),
        (".ssh/id_ed25519", vec![("PRIVATE_KEY", "FAKE-SECRET-007")]),
    ] {
        let contents = entries
            .into_iter()
            .map(|(label, id)| format!("{label}={}\n", secret(id)))
            .collect::<String>();
        std::fs::write(root.join(path), contents).expect("synthetic frozen secret file");
    }

    let content: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/golden/t1/project-content-canaries-v1.json"
    )))
    .expect("frozen project-content fixture");
    let marker = |id: &str| {
        content["canaries"]
            .as_array()
            .expect("frozen content list")
            .iter()
            .find(|item| item["id"] == id)
            .expect("frozen project marker id")["marker"]
            .as_str()
            .expect("frozen project marker")
    };
    for (name, id) in [
        ("AGENTS.md", "PROJ-CANARY-INSTRUCTION"),
        ("CLAUDE.md", "PROJ-CANARY-INSTRUCTION"),
        ("instructions/runne.md", "PROJ-CANARY-INSTRUCTION"),
        ("skills/canary.md", "PROJ-CANARY-SKILL"),
        ("hooks/pre.sh", "PROJ-CANARY-HOOK"),
        ("helpers/canary.py", "PROJ-CANARY-HELPER"),
        ("notes/plan.md", "PROJ-CANARY-FILE"),
        ("notes/unicode-nfc.txt", "PROJ-CANARY-UNICODE-NFC"),
        ("notes/unicode-nfd.txt", "PROJ-CANARY-UNICODE-NFD"),
        ("notes/managed-deny.txt", "PROJ-CANARY-MANAGED-DENY"),
    ] {
        std::fs::write(root.join(name), marker(id)).expect("synthetic hostile content file");
    }
    std::fs::write(
        root.join(".mcp.json"),
        format!(
            r#"{{"mcpServers":{{"fixture":{{"command":"helpers/canary.py","marker":"{}"}}}}}}"#,
            marker("PROJ-CANARY-MCP")
        ),
    )
    .expect("synthetic local MCP fixture");
}

pub(super) fn set_project_trust_status(
    database: &Path,
    status: runne_application::project_trust::ProjectTrustStatus,
) -> u64 {
    use runne_application::project_trust::{ProjectTrustPersistence, ProjectTrustProjectId};
    let connection = rusqlite::Connection::open(database).expect("open daemon authority database");
    let authority = runne_store::schema::read_authority_id(&connection)
        .expect("read authority id")
        .expect("authority id present");
    let project_id: [u8; 16] = connection
        .query_row("SELECT project_id FROM projects LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("project id present");
    drop(connection);
    let store = runne_store::ProjectTrustStore::open(database, authority)
        .expect("open durable project trust store");
    let project = ProjectTrustProjectId::from_bytes(project_id);
    let current = store.load(project).expect("load current trust record");
    store
        .commit(project, status, 0, current.token())
        .expect("commit current trust revision");
    store
        .load(project)
        .expect("read committed trust record")
        .revision
}

pub(super) fn current_project_trust(
    database: &Path,
) -> runne_application::project_trust::ProjectTrustRecord {
    use runne_application::project_trust::{ProjectTrustPersistence, ProjectTrustProjectId};
    let connection = rusqlite::Connection::open(database).expect("open daemon authority database");
    let authority = runne_store::schema::read_authority_id(&connection)
        .expect("read authority id")
        .expect("authority id present");
    let project_id: [u8; 16] = connection
        .query_row("SELECT project_id FROM projects LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("project id present");
    drop(connection);
    runne_store::ProjectTrustStore::open(database, authority)
        .expect("open durable project trust store")
        .load(ProjectTrustProjectId::from_bytes(project_id))
        .expect("load current trust record")
}

pub(super) fn assert_one_settled_dispatch(database: &Path) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("daemon database reader");
    let settled: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_dispatch_attempts attempt
             JOIN provider_terminal_outbox outbox ON outbox.dispatch_attempt_id = attempt.attempt_id
             JOIN provider_accounting_settlements accounting ON accounting.dispatch_attempt_id = attempt.attempt_id
             WHERE attempt.state = 5 AND attempt.settlement_digest = outbox.settlement_digest
               AND outbox.settlement_digest = accounting.settlement_digest
               AND length(attempt.settlement_digest) = 32 AND outbox.state = 2
               AND outbox.applied_at IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .expect("settled dispatch/accounting/outbox digest query");
    let attempts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_dispatch_attempts",
            [],
            |row| row.get(0),
        )
        .expect("dispatch attempt count");
    assert_eq!(attempts, 1, "one canonical attempt expected");
    assert_eq!(
        settled, 1,
        "one settled dispatch/accounting/outbox digest expected"
    );
}

pub(super) fn frozen_scanner() -> secret_scan::SecretScanner {
    let mut forbidden = nm10_rules::secret_patterns();
    forbidden.extend(nm10_rules::project_patterns());
    forbidden.push("RUNNE_T1_FAKE");
    let materials = forbidden
        .into_iter()
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();
    secret_scan::SecretScanner::new(material_representations(&materials))
        .unwrap_or_else(|_| panic!("frozen T1 scanner"))
}

pub(super) fn assert_profile_sqlite_absent(
    scanner: &secret_scan::SecretScanner,
    label: &str,
    database: &Path,
) {
    for suffix in ["", "-wal", "-shm"] {
        let mut path = database.as_os_str().to_owned();
        path.push(suffix);
        let path = Path::new(&path);
        if path.exists() {
            secret_scan::assert_file_absent(scanner, label, path);
        }
    }
}

pub(super) fn assert_uncertain_provider_effect(database: &Path) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("read uncertain provider effect");
    let counts: (i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_dispatch_attempts),
                    (SELECT COUNT(*) FROM provider_dispatch_attempts WHERE state = 6),
                    (SELECT COUNT(*) FROM provider_effect_starts),
                    (SELECT COUNT(*) FROM provider_terminal_outbox),
                    (SELECT COUNT(*) FROM provider_accounting_settlements)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("count uncertain provider state");
    assert_eq!(counts, (1, 1, 1, 0, 0));
}
