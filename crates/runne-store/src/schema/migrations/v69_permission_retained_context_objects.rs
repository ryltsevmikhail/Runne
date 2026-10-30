const V69_BINDING_DDL: &str = "CREATE TABLE x2_permission_bindings (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16 AND attempt_id!=zeroblob(16)),
 fence INTEGER NOT NULL CHECK(fence>0),
 invocation_id BLOB NOT NULL UNIQUE CHECK(length(invocation_id)=16 AND invocation_id!=zeroblob(16)),
 binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32 AND binding_digest!=zeroblob(32)),
 codec_version INTEGER NOT NULL CHECK(codec_version=1),
 binding BLOB NOT NULL CHECK(length(binding) BETWEEN 1 AND 1048576),
 native_owner_id BLOB NOT NULL CHECK(length(native_owner_id)=16 AND native_owner_id!=zeroblob(16)),
 native_owner_generation BLOB NOT NULL CHECK(length(native_owner_generation)=8 AND native_owner_generation!=zeroblob(8)),
 selection_managed_policy_version INTEGER NOT NULL CHECK(selection_managed_policy_version>=0),
 selection_managed_policy_digest BLOB NOT NULL CHECK(length(selection_managed_policy_digest)=32),
 captured_at INTEGER NOT NULL CHECK(captured_at>0),
 retained_context BLOB CHECK(retained_context IS NULL OR (typeof(retained_context)='blob' AND length(retained_context) BETWEEN 1 AND 1048576)),
 retained_context_digest BLOB CHECK(retained_context_digest IS NULL OR (typeof(retained_context_digest)='blob' AND length(retained_context_digest)=32)),
 PRIMARY KEY(taskrun_id,attempt_id),
 UNIQUE(taskrun_id,attempt_id,binding_digest),
 FOREIGN KEY(taskrun_id) REFERENCES taskrun_local_command_attempts(taskrun_id) ON DELETE RESTRICT,
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_assignments(taskrun_id,fence) ON DELETE RESTRICT
);";

const V69_PAIR_TRIGGER: (&str, &str) = (
    "x2_permission_bindings_context_pair_guard",
    "CREATE TRIGGER x2_permission_bindings_context_pair_guard BEFORE INSERT ON x2_permission_bindings WHEN (NEW.retained_context IS NULL) != (NEW.retained_context_digest IS NULL) BEGIN SELECT RAISE(ABORT,'X2 retained context requires exact pair'); END",
);

fn v69_binding_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    let mut expected = vec![
        "x2_permission_bindings_immutable".to_owned(),
        "x2_permission_bindings_no_delete".to_owned(),
        "x2_permission_bindings_route_guard".to_owned(),
        "schema_v12_fence_x2_permission_bindings_insert".to_owned(),
        V69_PAIR_TRIGGER.0.to_owned(),
    ];
    expected.sort();
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='x2_permission_bindings' ORDER BY name",
    )?;
    let actual = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<SqliteResult<Vec<_>>>()?;
    Ok(actual == expected
        && schema_trigger_matches(connection, V69_PAIR_TRIGGER.0, V69_PAIR_TRIGGER.1)?)
}

fn v69_context_rows_match(connection: &Connection) -> SqliteResult<bool> {
    use crate::store::taskrun_local_command::permission::retained_context::{
        CaptureContextRowV1, validate_optional_context_pair,
    };
    let mut statement = connection.prepare(
        "SELECT taskrun_id,attempt_id,invocation_id,fence,binding_digest,binding,native_owner_id,
         native_owner_generation,selection_managed_policy_version,selection_managed_policy_digest,
         retained_context,retained_context_digest FROM x2_permission_bindings",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let context: Option<Vec<u8>> = row.get(10)?;
        let context_digest: Option<Vec<u8>> = row.get(11)?;
        let array16 = |index| -> SqliteResult<[u8; 16]> {
            row.get::<_, Vec<u8>>(index)?
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)
        };
        let array32 = |index| -> SqliteResult<[u8; 32]> {
            row.get::<_, Vec<u8>>(index)?
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)
        };
        let generation: [u8; 8] = row
            .get::<_, Vec<u8>>(7)?
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let binding_digest = array32(4)?;
        let projection = CaptureContextRowV1 {
            taskrun_id: array16(0)?,
            attempt_id: array16(1)?,
            invocation_id: array16(2)?,
            fence: u64::try_from(row.get::<_, i64>(3)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            binding_digest,
            native_owner_id: array16(6)?,
            native_owner_generation: u64::from_be_bytes(generation),
            selection_managed_policy_version: u64::try_from(row.get::<_, i64>(8)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            selection_managed_policy_digest: array32(9)?,
        };
        let capture: Vec<u8> = row.get(5)?;
        if validate_optional_context_pair(
            context.as_deref(),
            context_digest.as_deref(),
            &capture,
            &binding_digest,
            &projection,
        )
        .is_err()
        {
            return Ok(false);
        }
    }
    Ok(true)
}
