pub(super) const MIGRATION_V42: &str = r#"
CREATE TABLE taskrun_fence_counters (
    taskrun_id BLOB PRIMARY KEY CHECK(length(taskrun_id) = 16 AND taskrun_id != zeroblob(16)),
    last_fence INTEGER NOT NULL CHECK(last_fence > 0)
);
CREATE TABLE taskrun_assignments (
    taskrun_id BLOB NOT NULL CHECK(length(taskrun_id) = 16 AND taskrun_id != zeroblob(16)),
    attempt_id BLOB NOT NULL UNIQUE CHECK(length(attempt_id) = 16 AND attempt_id != zeroblob(16)),
    node_id BLOB NOT NULL CHECK(length(node_id) = 16 AND node_id != zeroblob(16)),
    node_epoch INTEGER NOT NULL CHECK(node_epoch > 0),
    fence INTEGER NOT NULL CHECK(fence > 0),
    capability_descriptor TEXT NOT NULL CHECK(capability_descriptor = 'linux-executor-v1'),
    lease_expires_at_ms INTEGER NOT NULL CHECK(lease_expires_at_ms > 0),
    command_id BLOB NOT NULL CHECK(length(command_id) = 16),
    admitted_event_id BLOB NOT NULL UNIQUE CHECK(length(admitted_event_id) = 16),
    started_event_id BLOB NOT NULL UNIQUE CHECK(length(started_event_id) = 16),
    PRIMARY KEY(taskrun_id, fence)
);
CREATE INDEX taskrun_assignments_live_node ON taskrun_assignments(node_id, node_epoch);
CREATE TRIGGER taskrun_assignments_immutable BEFORE UPDATE ON taskrun_assignments BEGIN SELECT RAISE(ABORT, 'TaskRun assignment is immutable'); END;
CREATE TRIGGER taskrun_assignments_no_delete BEFORE DELETE ON taskrun_assignments BEGIN SELECT RAISE(ABORT, 'TaskRun assignment is immutable'); END;
CREATE TABLE taskrun_claim_receipts (
    command_id BLOB PRIMARY KEY CHECK(length(command_id) = 16),
    idempotency_scope_bytes BLOB NOT NULL,
    idempotency_key BLOB NOT NULL,
    fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32),
    taskrun_id BLOB NOT NULL CHECK(length(taskrun_id) = 16),
    attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
    node_id BLOB NOT NULL CHECK(length(node_id) = 16),
    node_epoch INTEGER NOT NULL CHECK(node_epoch > 0),
    fence INTEGER NOT NULL CHECK(fence > 0),
    lease_expires_at_ms INTEGER NOT NULL CHECK(lease_expires_at_ms > 0),
    new_version INTEGER NOT NULL CHECK(new_version > 0),
    admitted_event_id BLOB NOT NULL CHECK(length(admitted_event_id) = 16),
    started_event_id BLOB NOT NULL CHECK(length(started_event_id) = 16),
    UNIQUE(idempotency_scope_bytes, idempotency_key)
);
CREATE TRIGGER taskrun_claim_receipts_immutable BEFORE UPDATE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END;
CREATE TRIGGER taskrun_claim_receipts_no_delete BEFORE DELETE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END;
CREATE TRIGGER global_command_id_from_taskrun_claim_receipts
BEFORE INSERT ON taskrun_claim_receipts
WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id = NEW.command_id)
  OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id = NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
CREATE TRIGGER global_command_id_from_command_receipts_v42
BEFORE INSERT ON command_receipts
WHEN EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id = NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
CREATE TRIGGER global_command_id_from_project_workspace_receipts_v42
BEFORE INSERT ON project_workspace_command_receipts
WHEN EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id = NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
"#;

pub(super) fn apply_v42_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V42)?;
    for table in [
        "taskrun_fence_counters",
        "taskrun_assignments",
        "taskrun_claim_receipts",
    ] {
        for operation in ["insert", "update", "delete"] {
            transaction.execute_batch(&v12_fence_trigger(table, operation).1)?;
        }
    }
    transaction.execute("INSERT INTO schema_version (version) VALUES (42)", [])?;
    transaction.commit()
}

pub(super) fn v42_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 42 {
        return Ok(false);
    }
    v42_structure_matches(connection, false)
}

include!("v42_taskrun_claim_validation.rs");
include!("v42_local_ext.rs");
