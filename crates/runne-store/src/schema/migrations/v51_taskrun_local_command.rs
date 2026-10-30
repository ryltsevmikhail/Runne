pub(super) const MIGRATION_V51: &str = r#"
CREATE TABLE taskrun_local_command_attempts (
 taskrun_id BLOB PRIMARY KEY CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 conversation_id BLOB NOT NULL CHECK(length(conversation_id)=16),
 workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16),
 attempt_id BLOB CHECK(attempt_id IS NULL OR length(attempt_id)=16),
 node_id BLOB CHECK(node_id IS NULL OR length(node_id)=16),
 node_epoch INTEGER CHECK(node_epoch IS NULL OR node_epoch>0),
 fence INTEGER CHECK(fence IS NULL OR fence>0),
 command_digest BLOB NOT NULL CHECK(length(command_digest)=32),
 executable_digest BLOB CHECK(executable_digest IS NULL OR length(executable_digest)=32),
 workspace_version INTEGER CHECK(workspace_version IS NULL OR workspace_version>0),
 admitted_root_version INTEGER CHECK(admitted_root_version IS NULL OR admitted_root_version>0),
 admitted_root_identity BLOB CHECK(admitted_root_identity IS NULL OR length(admitted_root_identity)=32),
 trust_epoch INTEGER CHECK(trust_epoch IS NULL OR trust_epoch>0),
 trust_revision INTEGER CHECK(trust_revision IS NULL OR trust_revision>0),
 source_policy_version INTEGER CHECK(source_policy_version IS NULL OR source_policy_version=2),
 command_policy_version INTEGER CHECK(command_policy_version IS NULL OR command_policy_version=1),
 approval_id BLOB CHECK(approval_id IS NULL OR length(approval_id)=16),
 managed_area_identity BLOB CHECK(managed_area_identity IS NULL OR length(managed_area_identity)=100),
 state TEXT NOT NULL CHECK(state IN ('preflight','approval_pending','approved','launch_intent','release_reserved','running','cancel_requested','completed','cancelled','denied','no_effect_terminal','stop_unconfirmed','outcome_unknown')),
 stdout BLOB NOT NULL DEFAULT X'' CHECK(length(stdout)<=65536),
 stderr BLOB NOT NULL DEFAULT X'' CHECK(length(stderr)<=65536),
 exit_code INTEGER CHECK(exit_code IS NULL OR exit_code BETWEEN 0 AND 255),
 updated_at INTEGER NOT NULL CHECK(updated_at>=0),
 CHECK((attempt_id IS NULL AND node_id IS NULL AND node_epoch IS NULL AND fence IS NULL) OR (attempt_id IS NOT NULL AND node_id IS NOT NULL AND node_epoch IS NOT NULL AND fence IS NOT NULL AND length(attempt_id)=16 AND length(node_id)=16 AND node_epoch>0 AND fence>0)),
 CHECK((workspace_version IS NULL AND admitted_root_version IS NULL AND admitted_root_identity IS NULL AND trust_epoch IS NULL AND trust_revision IS NULL AND source_policy_version IS NULL AND command_policy_version IS NULL AND executable_digest IS NULL) OR (workspace_version IS NOT NULL AND admitted_root_version IS NOT NULL AND admitted_root_identity IS NOT NULL AND trust_epoch IS NOT NULL AND trust_revision IS NOT NULL AND source_policy_version IS NOT NULL AND command_policy_version IS NOT NULL AND executable_digest IS NOT NULL))
);
CREATE UNIQUE INDEX taskrun_local_command_writer_active ON taskrun_local_command_attempts(conversation_id) WHERE state NOT IN ('completed','cancelled','denied','no_effect_terminal');
CREATE TRIGGER taskrun_local_command_identity_immutable BEFORE UPDATE ON taskrun_local_command_attempts
WHEN NEW.taskrun_id!=OLD.taskrun_id OR NEW.conversation_id!=OLD.conversation_id OR NEW.workspace_id!=OLD.workspace_id OR NEW.command_digest!=OLD.command_digest OR (OLD.attempt_id IS NOT NULL AND NEW.attempt_id IS NOT OLD.attempt_id) OR (OLD.node_id IS NOT NULL AND NEW.node_id IS NOT OLD.node_id) OR (OLD.node_epoch IS NOT NULL AND NEW.node_epoch IS NOT OLD.node_epoch) OR (OLD.fence IS NOT NULL AND NEW.fence IS NOT OLD.fence) OR (OLD.executable_digest IS NOT NULL AND NEW.executable_digest IS NOT OLD.executable_digest) OR (OLD.workspace_version IS NOT NULL AND NEW.workspace_version IS NOT OLD.workspace_version) OR (OLD.admitted_root_version IS NOT NULL AND NEW.admitted_root_version IS NOT OLD.admitted_root_version) OR (OLD.admitted_root_identity IS NOT NULL AND NEW.admitted_root_identity IS NOT OLD.admitted_root_identity) OR (OLD.trust_epoch IS NOT NULL AND NEW.trust_epoch IS NOT OLD.trust_epoch) OR (OLD.trust_revision IS NOT NULL AND NEW.trust_revision IS NOT OLD.trust_revision) OR (OLD.source_policy_version IS NOT NULL AND NEW.source_policy_version IS NOT OLD.source_policy_version) OR (OLD.command_policy_version IS NOT NULL AND NEW.command_policy_version IS NOT OLD.command_policy_version) OR (OLD.approval_id IS NOT NULL AND NEW.approval_id IS NOT OLD.approval_id) OR (OLD.managed_area_identity IS NOT NULL AND NEW.managed_area_identity IS NOT OLD.managed_area_identity)
BEGIN SELECT RAISE(ABORT,'TaskRun local command identity is immutable'); END;
CREATE TRIGGER taskrun_local_command_state_transition BEFORE UPDATE OF state ON taskrun_local_command_attempts
WHEN NOT ((OLD.state='preflight' AND NEW.state IN ('approval_pending','approved','denied','no_effect_terminal','outcome_unknown')) OR (OLD.state='approval_pending' AND NEW.state IN ('approved','denied','no_effect_terminal','outcome_unknown')) OR (OLD.state='approved' AND NEW.state IN ('launch_intent','denied','no_effect_terminal','outcome_unknown')) OR (OLD.state='launch_intent' AND NEW.state IN ('release_reserved','cancel_requested','stop_unconfirmed','outcome_unknown')) OR (OLD.state='release_reserved' AND NEW.state IN ('running','cancel_requested','stop_unconfirmed','outcome_unknown')) OR (OLD.state='running' AND NEW.state IN ('completed','cancel_requested','stop_unconfirmed','outcome_unknown')) OR (OLD.state='cancel_requested' AND NEW.state IN ('cancelled','stop_unconfirmed','outcome_unknown')) OR (OLD.state='stop_unconfirmed' AND NEW.state IN ('cancelled','outcome_unknown')) OR (OLD.state='outcome_unknown' AND NEW.state IN ('cancelled','completed','stop_unconfirmed')))
BEGIN SELECT RAISE(ABORT,'TaskRun local command state transition is invalid'); END;
CREATE TRIGGER taskrun_local_command_no_delete BEFORE DELETE ON taskrun_local_command_attempts BEGIN SELECT RAISE(ABORT,'TaskRun local command record is retained'); END;
"#;

pub(super) fn apply_v51_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V51)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("taskrun_local_command_attempts", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(51)", [])?;
    tx.commit()
}

pub(super) fn v51_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 51 || !v50_base_matches(connection, version)? {
        return Ok(false);
    }
    v51_schema_matches(connection)
}

/// Validates the frozen V51 objects when a later schema version is installed.
pub(super) fn v51_base_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 52..=71) {
        return Ok(false);
    }
    if !v50_base_matches(connection, version)? {
        return Ok(false);
    }
    let matches = v51_schema_matches(connection)?;
    Ok(matches)
}

fn v51_schema_matches(connection: &Connection) -> SqliteResult<bool> {
    for (kind, name, expected) in [
        (
            "table",
            "taskrun_local_command_attempts",
            MIGRATION_V51.split(';').next().unwrap_or_default(),
        ),
        (
            "index",
            "taskrun_local_command_writer_active",
            "CREATE UNIQUE INDEX taskrun_local_command_writer_active ON taskrun_local_command_attempts(conversation_id) WHERE state NOT IN ('completed','cancelled','denied','no_effect_terminal')",
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                rusqlite::params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        let ddl = if kind == "table" {
            normalize_ddl(expected)
        } else {
            normalize_sql(expected)
        };
        if actual.is_none_or(|sql| {
            if kind == "table" {
                normalize_ddl(&sql) != ddl
            } else {
                normalize_sql(&sql) != ddl
            }
        }) {
            return Ok(false);
        }
    }
    for (name, expected) in [
        (
            "taskrun_local_command_identity_immutable",
            "CREATE TRIGGER taskrun_local_command_identity_immutable BEFORE UPDATE ON taskrun_local_command_attempts WHEN NEW.taskrun_id!=OLD.taskrun_id OR NEW.conversation_id!=OLD.conversation_id OR NEW.workspace_id!=OLD.workspace_id OR NEW.command_digest!=OLD.command_digest OR (OLD.attempt_id IS NOT NULL AND NEW.attempt_id IS NOT OLD.attempt_id) OR (OLD.node_id IS NOT NULL AND NEW.node_id IS NOT OLD.node_id) OR (OLD.node_epoch IS NOT NULL AND NEW.node_epoch IS NOT OLD.node_epoch) OR (OLD.fence IS NOT NULL AND NEW.fence IS NOT OLD.fence) OR (OLD.executable_digest IS NOT NULL AND NEW.executable_digest IS NOT OLD.executable_digest) OR (OLD.workspace_version IS NOT NULL AND NEW.workspace_version IS NOT OLD.workspace_version) OR (OLD.admitted_root_version IS NOT NULL AND NEW.admitted_root_version IS NOT OLD.admitted_root_version) OR (OLD.admitted_root_identity IS NOT NULL AND NEW.admitted_root_identity IS NOT OLD.admitted_root_identity) OR (OLD.trust_epoch IS NOT NULL AND NEW.trust_epoch IS NOT OLD.trust_epoch) OR (OLD.trust_revision IS NOT NULL AND NEW.trust_revision IS NOT OLD.trust_revision) OR (OLD.source_policy_version IS NOT NULL AND NEW.source_policy_version IS NOT OLD.source_policy_version) OR (OLD.command_policy_version IS NOT NULL AND NEW.command_policy_version IS NOT OLD.command_policy_version) OR (OLD.approval_id IS NOT NULL AND NEW.approval_id IS NOT OLD.approval_id) OR (OLD.managed_area_identity IS NOT NULL AND NEW.managed_area_identity IS NOT OLD.managed_area_identity) BEGIN SELECT RAISE(ABORT,'TaskRun local command identity is immutable'); END",
        ),
        (
            "taskrun_local_command_state_transition",
            "CREATE TRIGGER taskrun_local_command_state_transition BEFORE UPDATE OF state ON taskrun_local_command_attempts WHEN NOT ((OLD.state='preflight' AND NEW.state IN ('approval_pending','approved','denied','no_effect_terminal','outcome_unknown')) OR (OLD.state='approval_pending' AND NEW.state IN ('approved','denied','no_effect_terminal','outcome_unknown')) OR (OLD.state='approved' AND NEW.state IN ('launch_intent','denied','no_effect_terminal','outcome_unknown')) OR (OLD.state='launch_intent' AND NEW.state IN ('release_reserved','cancel_requested','stop_unconfirmed','outcome_unknown')) OR (OLD.state='release_reserved' AND NEW.state IN ('running','cancel_requested','stop_unconfirmed','outcome_unknown')) OR (OLD.state='running' AND NEW.state IN ('completed','cancel_requested','stop_unconfirmed','outcome_unknown')) OR (OLD.state='cancel_requested' AND NEW.state IN ('cancelled','stop_unconfirmed','outcome_unknown')) OR (OLD.state='stop_unconfirmed' AND NEW.state IN ('cancelled','outcome_unknown')) OR (OLD.state='outcome_unknown' AND NEW.state IN ('cancelled','completed','stop_unconfirmed'))) BEGIN SELECT RAISE(ABORT,'TaskRun local command state transition is invalid'); END",
        ),
        (
            "taskrun_local_command_no_delete",
            "CREATE TRIGGER taskrun_local_command_no_delete BEFORE DELETE ON taskrun_local_command_attempts BEGIN SELECT RAISE(ABORT,'TaskRun local command record is retained'); END",
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|sql| normalize_sql(&sql) != normalize_sql(expected)) {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) = v12_fence_trigger("taskrun_local_command_attempts", operation);
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [&name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|sql| normalize_sql(&sql) != normalize_sql(&expected)) {
            return Ok(false);
        }
    }
    Ok(true)
}
