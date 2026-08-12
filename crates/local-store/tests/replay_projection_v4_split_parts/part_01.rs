use std::path::Path;

use gocode_local_store::{
    AppliedReplayEvent, LocalStore, ReplayApplyOutcome, ReplayCheckpoint, ReplayScopeKey,
    ReplayStoreError, ReplayTransition, StoreOpenError, pre_v4_migration_backup_path,
    verify_pre_v4_migration_backup,
};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

const BINDING_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_BINDING_DIGEST: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn scope() -> ReplayScopeKey {
    ReplayScopeKey {
        runtime_authority: "runtime-1".into(),
        principal: "principal-1".into(),
        lineage: "lineage-1".into(),
        scope: "conversation-1".into(),
        binding_digest: BINDING_DIGEST.into(),
    }
}

fn other_scope() -> ReplayScopeKey {
    ReplayScopeKey {
        scope: "conversation-2".into(),
        ..scope()
    }
}

#[allow(clippy::too_many_arguments)]
fn transition<'a>(
    scope: &'a ReplayScopeKey,
    expected_checkpoint: Option<&'a ReplayCheckpoint>,
    event_id: &'a str,
    cursor: &'a str,
    generation: u64,
    event_sequence: u64,
    event_bytes: &'a [u8],
    projection_revision: u64,
    projection_bytes: &'a [u8],
) -> ReplayTransition<'a> {
    ReplayTransition {
        scope,
        expected_checkpoint,
        event_id,
        cursor,
        generation,
        event_sequence,
        event_bytes,
        event_digest: digest(event_bytes),
        projection_revision,
        projection_bytes,
        projection_digest: digest(projection_bytes),
    }
}

fn create_v3_database(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("create v3 database");
    connection
        .execute_batch(
            "
            CREATE TABLE settings (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL,
                revision INTEGER NOT NULL DEFAULT 1
            ) STRICT;
            INSERT INTO settings (key, value) VALUES ('appearance.theme', 'light');

            CREATE TABLE projects (
                id INTEGER PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                last_opened_at INTEGER NOT NULL
            ) STRICT;
            INSERT INTO projects (id, name, path, last_opened_at)
            VALUES (41, 'preserved', '/tmp/preserved-project', 17);

            CREATE TABLE meta (
                singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
                db_generation INTEGER NOT NULL CHECK (db_generation >= 1),
                last_transaction_digest TEXT,
                commit_marker INTEGER NOT NULL DEFAULT 0 CHECK (commit_marker IN (0, 1))
            ) STRICT;
            INSERT INTO meta (singleton, schema_version, db_generation) VALUES (1, 3, 9);

            CREATE TABLE drafts (
                runtime_authority TEXT NOT NULL, principal TEXT NOT NULL, project_id TEXT NOT NULL,
                run_id TEXT NOT NULL, body TEXT NOT NULL, revision INTEGER NOT NULL CHECK (revision >= 1),
                updated_at INTEGER NOT NULL CHECK (updated_at >= 0), PRIMARY KEY (runtime_authority, principal, project_id, run_id)
            ) STRICT;

            CREATE TABLE mutation_ledger (
                runtime_authority TEXT NOT NULL, principal TEXT NOT NULL, operation_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL, target TEXT NOT NULL, disposition TEXT NOT NULL,
                PRIMARY KEY (runtime_authority, principal, operation_id),
                UNIQUE (runtime_authority, principal, idempotency_key)
            ) STRICT;

            CREATE TABLE window_layout (
                profile TEXT NOT NULL, display_topology TEXT NOT NULL, geometry TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK (revision >= 1),
                PRIMARY KEY (profile, display_topology)
            ) STRICT;

            CREATE TABLE projections (
                runtime_authority TEXT NOT NULL,
                principal TEXT NOT NULL,
                lineage TEXT NOT NULL,
                scope TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                cursor TEXT NOT NULL,
                payload BLOB NOT NULL,
                PRIMARY KEY (runtime_authority, principal, lineage, scope)
            ) STRICT;

            CREATE TABLE event_journal (
                runtime_authority TEXT NOT NULL,
                principal TEXT NOT NULL,
                lineage TEXT NOT NULL,
                scope TEXT NOT NULL,
                event_id TEXT NOT NULL,
                cursor TEXT NOT NULL,
                validated_envelope BLOB NOT NULL,
                digest TEXT NOT NULL,
                PRIMARY KEY (runtime_authority, principal, lineage, scope, event_id)
            ) STRICT;

            CREATE TABLE replay_cursors (
                runtime_authority TEXT NOT NULL,
                principal TEXT NOT NULL,
                lineage TEXT NOT NULL,
                scope TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                applied_cursor TEXT NOT NULL,
                PRIMARY KEY (runtime_authority, principal, lineage, scope)
            ) STRICT;

            PRAGMA user_version = 3;
            ",
        )
        .expect("create v3 schema");
    connection
}
