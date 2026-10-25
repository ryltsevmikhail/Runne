macro_rules! sidecar_row_guard {
    ($table:literal, $suffix:literal, $operation:literal, $message:literal) => {
        (
            concat!($table, $suffix),
            concat!(
                "CREATE TRIGGER ",
                $table,
                $suffix,
                " BEFORE ",
                $operation,
                " ON ",
                $table,
                " BEGIN SELECT RAISE(ABORT,'",
                $message,
                "'); END"
            ),
        )
    };
}
macro_rules! insert_fence_trigger {
    ($table:literal) => {
        (
            concat!("schema_v12_fence_", $table, "_insert"),
            concat!("CREATE TRIGGER schema_v12_fence_", $table, "_insert AFTER INSERT ON ", $table, " BEGIN INSERT INTO schema_upgrade_write_latch(id,closed) VALUES(1,1) ON CONFLICT(id) DO NOTHING; END"),
        )
    };
}

const V68_SIDECAR_TABLES: &[&str] = &[
    "x2_permission_bindings",
    "x2_permission_human",
    "x2_permission_admission",
    "x2_permission_spent",
    "x2_permission_stop",
    "x2_permission_terminal",
];
const V68_SIDECAR_TRIGGERS: &[(&str, &str)] = &[
    sidecar_row_guard!(
        "x2_permission_bindings",
        "_immutable",
        "UPDATE",
        "X2 permission binding is immutable"
    ),
    sidecar_row_guard!(
        "x2_permission_bindings",
        "_no_delete",
        "DELETE",
        "X2 permission binding is retained"
    ),
    sidecar_row_guard!(
        "x2_permission_human",
        "_immutable",
        "UPDATE",
        "X2 human proof is immutable"
    ),
    sidecar_row_guard!(
        "x2_permission_human",
        "_no_delete",
        "DELETE",
        "X2 human proof is retained"
    ),
    sidecar_row_guard!(
        "x2_permission_admission",
        "_immutable",
        "UPDATE",
        "X2 admission is immutable"
    ),
    sidecar_row_guard!(
        "x2_permission_admission",
        "_no_delete",
        "DELETE",
        "X2 admission is retained"
    ),
    sidecar_row_guard!(
        "x2_permission_spent",
        "_immutable",
        "UPDATE",
        "X2 spend is immutable"
    ),
    sidecar_row_guard!(
        "x2_permission_spent",
        "_no_delete",
        "DELETE",
        "X2 spend is retained"
    ),
    sidecar_row_guard!(
        "x2_permission_stop",
        "_immutable",
        "UPDATE",
        "X2 stop is immutable"
    ),
    sidecar_row_guard!(
        "x2_permission_stop",
        "_no_delete",
        "DELETE",
        "X2 stop is retained"
    ),
    sidecar_row_guard!(
        "x2_permission_terminal",
        "_immutable",
        "UPDATE",
        "X2 terminal is immutable"
    ),
    sidecar_row_guard!(
        "x2_permission_terminal",
        "_no_delete",
        "DELETE",
        "X2 terminal is retained"
    ),
    (
        "x2_permission_bindings_route_guard",
        "CREATE TRIGGER x2_permission_bindings_route_guard BEFORE INSERT ON x2_permission_bindings WHEN NOT EXISTS(SELECT 1 FROM taskrun_local_permission_routes r JOIN taskrun_local_command_attempts a USING(taskrun_id) JOIN taskrun_assignments x ON x.taskrun_id=r.taskrun_id AND x.fence=NEW.fence JOIN taskrun_claim_receipts c ON c.taskrun_id=x.taskrun_id AND c.fence=x.fence AND c.attempt_id=x.attempt_id WHERE r.taskrun_id=NEW.taskrun_id AND r.route=2 AND r.provenance=3 AND r.cutover_version=68 AND x.attempt_id=NEW.attempt_id AND a.executable_digest IS NULL AND a.approval_id IS NULL) BEGIN SELECT RAISE(ABORT,'X2 binding requires current permission route and assignment'); END",
    ),
    (
        "x2_permission_human_approval_guard",
        "CREATE TRIGGER x2_permission_human_approval_guard BEFORE INSERT ON x2_permission_human WHEN NOT EXISTS(SELECT 1 FROM x2_permission_bindings b JOIN taskrun_local_command_attempts l USING(taskrun_id) JOIN workspaces w ON w.workspace_id=l.workspace_id JOIN approvals a ON a.approval_id=lower(substr(hex(NEW.approval_id),1,8)||'-'||substr(hex(NEW.approval_id),9,4)||'-'||substr(hex(NEW.approval_id),13,4)||'-'||substr(hex(NEW.approval_id),17,4)||'-'||substr(hex(NEW.approval_id),21,12)) WHERE b.taskrun_id=NEW.taskrun_id AND b.attempt_id=NEW.attempt_id AND b.binding_digest=NEW.binding_digest AND a.task_run_id=lower(substr(hex(NEW.taskrun_id),1,8)||'-'||substr(hex(NEW.taskrun_id),9,4)||'-'||substr(hex(NEW.taskrun_id),13,4)||'-'||substr(hex(NEW.taskrun_id),17,4)||'-'||substr(hex(NEW.taskrun_id),21,12)) AND a.attempt_id=lower(substr(hex(NEW.attempt_id),1,8)||'-'||substr(hex(NEW.attempt_id),9,4)||'-'||substr(hex(NEW.attempt_id),13,4)||'-'||substr(hex(NEW.attempt_id),17,4)||'-'||substr(hex(NEW.attempt_id),21,12)) AND a.invocation_id=lower(substr(hex(b.invocation_id),1,8)||'-'||substr(hex(b.invocation_id),9,4)||'-'||substr(hex(b.invocation_id),13,4)||'-'||substr(hex(b.invocation_id),17,4)||'-'||substr(hex(b.invocation_id),21,12)) AND a.resource='taskrun:'||lower(substr(hex(NEW.taskrun_id),1,8)||'-'||substr(hex(NEW.taskrun_id),9,4)||'-'||substr(hex(NEW.taskrun_id),13,4)||'-'||substr(hex(NEW.taskrun_id),17,4)||'-'||substr(hex(NEW.taskrun_id),21,12))||':workspace:'||lower(substr(hex(l.workspace_id),1,8)||'-'||substr(hex(l.workspace_id),9,4)||'-'||substr(hex(l.workspace_id),13,4)||'-'||substr(hex(l.workspace_id),17,4)||'-'||substr(hex(l.workspace_id),21,12)) AND a.principal_id=w.principal_id AND a.action='local_command.execute' AND a.action_digest=NEW.approval_digest AND a.request_version=2 AND a.expires_at>NEW.accepted_at AND a.state=2 AND a.decision=1 AND a.decision_principal_id=a.principal_id AND a.decided_at=NEW.accepted_at) BEGIN SELECT RAISE(ABORT,'X2 human proof requires exact accepted approval'); END",
    ),
    (
        "x2_permission_terminal_receipt_guard",
        "CREATE TRIGGER x2_permission_terminal_receipt_guard BEFORE INSERT ON x2_permission_terminal WHEN NOT EXISTS(SELECT 1 FROM taskrun_local_permission_routes r JOIN taskrun_local_command_attempts a USING(taskrun_id) WHERE r.taskrun_id=NEW.taskrun_id AND r.route=2 AND a.attempt_id=NEW.attempt_id AND a.fence=NEW.fence AND ((NEW.terminal_kind=1 AND a.managed_area_identity=(SELECT area_identity FROM x2_permission_spent s WHERE s.taskrun_id=NEW.taskrun_id AND s.attempt_id=NEW.attempt_id) AND EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts t WHERE t.taskrun_id=NEW.taskrun_id AND t.fence=NEW.fence AND t.attempt_id=NEW.attempt_id AND t.terminal_event_id=NEW.event_id AND t.terminal_version=NEW.terminal_version)) OR (NEW.terminal_kind=2 AND NOT EXISTS(SELECT 1 FROM x2_permission_spent s WHERE s.taskrun_id=NEW.taskrun_id AND s.attempt_id=NEW.attempt_id) AND EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts n WHERE n.taskrun_id=NEW.taskrun_id AND n.fence=NEW.fence AND n.attempt_id=NEW.attempt_id AND n.failure_event_id=NEW.event_id AND n.new_version=NEW.terminal_version)))) BEGIN SELECT RAISE(ABORT,'X2 terminal requires exact no-replay settlement'); END",
    ),
];
const V68_SIDECAR_FENCE_TRIGGERS: &[(&str, &str)] = &[
    insert_fence_trigger!("x2_permission_bindings"),
    insert_fence_trigger!("x2_permission_human"),
    insert_fence_trigger!("x2_permission_admission"),
    insert_fence_trigger!("x2_permission_spent"),
    insert_fence_trigger!("x2_permission_stop"),
    insert_fence_trigger!("x2_permission_terminal"),
];

fn v68_sidecars_match(connection: &Connection) -> SqliteResult<bool> {
    for table in V68_SIDECAR_TABLES {
        if !table_sql_matches_migration(connection, table, MIGRATION_V68)? {
            return Ok(false);
        }
    }
    v68_sidecar_rows_match(connection)
}

fn v68_sidecar_rows_match(connection: &Connection) -> SqliteResult<bool> {
    let invalid: i64 = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM x2_permission_bindings b LEFT JOIN taskrun_local_permission_routes r USING(taskrun_id) JOIN taskrun_local_command_attempts a USING(taskrun_id) LEFT JOIN taskrun_assignments x ON x.taskrun_id=b.taskrun_id AND x.fence=b.fence WHERE r.taskrun_id IS NULL OR r.route!=2 OR r.provenance!=3 OR x.taskrun_id IS NULL OR x.attempt_id!=b.attempt_id OR a.attempt_id IS NOT NULL AND (a.attempt_id!=b.attempt_id OR a.fence!=b.fence) OR a.executable_digest IS NOT NULL OR a.approval_id IS NOT NULL)
             +(SELECT COUNT(*) FROM x2_permission_human h LEFT JOIN x2_permission_bindings b ON b.taskrun_id=h.taskrun_id AND b.attempt_id=h.attempt_id AND b.binding_digest=h.binding_digest LEFT JOIN taskrun_local_command_attempts l ON l.taskrun_id=h.taskrun_id LEFT JOIN workspaces w ON w.workspace_id=l.workspace_id LEFT JOIN approvals a ON a.approval_id=lower(substr(hex(h.approval_id),1,8)||'-'||substr(hex(h.approval_id),9,4)||'-'||substr(hex(h.approval_id),13,4)||'-'||substr(hex(h.approval_id),17,4)||'-'||substr(hex(h.approval_id),21,12)) WHERE b.taskrun_id IS NULL OR a.approval_id IS NULL OR a.action!='local_command.execute' OR a.action_digest!=h.approval_digest OR a.request_version!=2 OR a.expires_at<=h.accepted_at OR a.state!=2 OR a.decision!=1 OR a.decision_principal_id!=a.principal_id OR a.decided_at!=h.accepted_at OR a.task_run_id!=lower(substr(hex(h.taskrun_id),1,8)||'-'||substr(hex(h.taskrun_id),9,4)||'-'||substr(hex(h.taskrun_id),13,4)||'-'||substr(hex(h.taskrun_id),17,4)||'-'||substr(hex(h.taskrun_id),21,12)) OR a.attempt_id!=lower(substr(hex(h.attempt_id),1,8)||'-'||substr(hex(h.attempt_id),9,4)||'-'||substr(hex(h.attempt_id),13,4)||'-'||substr(hex(h.attempt_id),17,4)||'-'||substr(hex(h.attempt_id),21,12)) OR a.invocation_id!=lower(substr(hex(b.invocation_id),1,8)||'-'||substr(hex(b.invocation_id),9,4)||'-'||substr(hex(b.invocation_id),13,4)||'-'||substr(hex(b.invocation_id),17,4)||'-'||substr(hex(b.invocation_id),21,12)) OR a.principal_id!=w.principal_id OR a.resource!='taskrun:'||lower(substr(hex(h.taskrun_id),1,8)||'-'||substr(hex(h.taskrun_id),9,4)||'-'||substr(hex(h.taskrun_id),13,4)||'-'||substr(hex(h.taskrun_id),17,4)||'-'||substr(hex(h.taskrun_id),21,12))||':workspace:'||lower(substr(hex(l.workspace_id),1,8)||'-'||substr(hex(l.workspace_id),9,4)||'-'||substr(hex(l.workspace_id),13,4)||'-'||substr(hex(l.workspace_id),17,4)||'-'||substr(hex(l.workspace_id),21,12)))
             +(SELECT COUNT(*) FROM x2_permission_admission p JOIN x2_permission_bindings b USING(taskrun_id,attempt_id,binding_digest) WHERE p.admission_kind=2 AND NOT EXISTS(SELECT 1 FROM x2_permission_human h WHERE h.taskrun_id=p.taskrun_id AND h.attempt_id=p.attempt_id AND h.proof_digest=p.proof_digest))
             +(SELECT COUNT(*) FROM x2_permission_spent s JOIN taskrun_local_command_attempts a USING(taskrun_id) JOIN x2_permission_bindings b USING(taskrun_id,attempt_id) WHERE a.attempt_id!=s.attempt_id OR a.fence!=b.fence OR b.invocation_id!=s.invocation_id OR a.managed_area_identity!=s.area_identity OR s.owner_id!=b.native_owner_id OR s.owner_generation!=b.native_owner_generation OR s.owner_generation=zeroblob(8))
             +(SELECT COUNT(*) FROM x2_permission_stop s LEFT JOIN events e ON e.event_id=s.event_id LEFT JOIN x2_permission_bindings b ON b.taskrun_id=s.taskrun_id AND b.attempt_id=s.attempt_id AND b.binding_digest=s.binding_digest WHERE b.taskrun_id IS NULL OR e.event_id IS NULL OR e.aggregate_type!=1 OR e.aggregate_id!=s.taskrun_id OR e.sequence!=s.observed_version)
             +(SELECT COUNT(*) FROM x2_permission_terminal x LEFT JOIN events e ON e.event_id=x.event_id WHERE e.event_id IS NULL OR e.aggregate_type!=1 OR e.aggregate_id!=x.taskrun_id OR (x.terminal_kind=1 AND (NOT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts v WHERE v.taskrun_id=x.taskrun_id AND v.fence=x.fence AND v.attempt_id=x.attempt_id AND v.terminal_event_id=x.event_id AND v.terminal_version=x.terminal_version) OR NOT EXISTS(SELECT 1 FROM x2_permission_spent s WHERE s.taskrun_id=x.taskrun_id AND s.attempt_id=x.attempt_id) OR x.exit_kind=1 AND (SELECT exit_code FROM taskrun_local_command_attempts a WHERE a.taskrun_id=x.taskrun_id)!=x.exit_code OR x.exit_kind=2 AND (SELECT exit_code FROM taskrun_local_command_attempts a WHERE a.taskrun_id=x.taskrun_id)!=128+x.signal)) OR (x.terminal_kind=2 AND (EXISTS(SELECT 1 FROM x2_permission_spent s WHERE s.taskrun_id=x.taskrun_id AND s.attempt_id=x.attempt_id) OR NOT EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts n WHERE n.taskrun_id=x.taskrun_id AND n.fence=x.fence AND n.attempt_id=x.attempt_id AND n.failure_event_id=x.event_id AND n.new_version=x.terminal_version))))",
        [],
        |row| row.get(0),
    )?;
    if invalid != 0 {
        return Ok(false);
    }
    v68_binding_rows_match(connection)
}

fn v68_binding_rows_match(connection: &Connection) -> SqliteResult<bool> {
    let mut statement = connection.prepare(
        "SELECT b.taskrun_id,b.attempt_id,b.fence,b.invocation_id,b.binding_digest,b.binding,
                b.native_owner_id,b.native_owner_generation,a.command_digest,a.workspace_id,
                b.selection_managed_policy_version,b.selection_managed_policy_digest
         FROM x2_permission_bindings b
         JOIN taskrun_local_command_attempts a USING(taskrun_id)",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, Vec<u8>>(7)?,
            row.get::<_, Vec<u8>>(8)?,
            row.get::<_, Vec<u8>>(9)?,
            row.get::<_, i64>(10)?,
            row.get::<_, Vec<u8>>(11)?,
        ))
    })?;
    for row in rows {
        let (
            taskrun,
            attempt,
            fence,
            invocation,
            digest,
            bytes,
            owner,
            generation,
            command,
            workspace,
            selection_policy_version,
            selection_policy_digest,
        ) = row?;
        let Ok(capture) = crate::store::taskrun_local_command::permission::codec::decode(&bytes)
        else {
            return Ok(false);
        };
        let identity = connection.query_row(
            "SELECT attempt_id,node_id,node_epoch FROM taskrun_assignments WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![&taskrun, fence],
            |row| Ok((row.get::<_, Vec<u8>>(0)?,row.get::<_, Vec<u8>>(1)?,row.get::<_, i64>(2)?)),
        );
        let Ok((assigned_attempt, node, node_epoch)) = identity else {
            return Ok(false);
        };
        let owner_generation: [u8; 8] = match generation.as_slice().try_into() {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let Ok(node_id) = uuid::Uuid::parse_str(&capture.node_id) else {
            return Ok(false);
        };
        let workspace_owner: Option<(Vec<u8>, String)> = connection
            .query_row(
                "SELECT project_id,principal_id FROM workspaces WHERE workspace_id=?1",
                [&workspace],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((project_id, principal_id)) = workspace_owner else {
            return Ok(false);
        };
        let valid =
            crate::store::taskrun_local_command::permission::codec::digest_matches(&bytes, &digest)
                && capture.taskrun_id.as_slice() == taskrun
                && capture.attempt_id.as_slice() == attempt
                && capture.invocation_id.as_slice() == invocation
                && capture.fence == u64::try_from(fence).unwrap_or(0)
                && capture.command_digest.as_slice() == command
                && capture.workspace_id.as_slice() == workspace
                && capture.project_id.as_slice() == project_id
                && capture.principal_id == principal_id
                && capture.native_owner_id.as_slice() == owner
                && capture.native_owner_generation.to_be_bytes() == owner_generation
                && capture.native_owner_generation != 0
                && capture.claim_stream_version > 0
                && capture.node_epoch == u64::try_from(node_epoch).unwrap_or(0)
                && node_id.as_bytes().as_slice() == node
                && assigned_attempt == attempt
                && capture.workspace_version > 0
                && capture.project_version > 0
                && capture.root_version > 0
                && capture.trust_epoch > 0
                && capture.trust_revision > 0
                && capture.source_policy_version == 2
                && capture.command_policy_version == 1
                && capture.preset_version == 1
                && capture.authorization_revision <= i64::MAX as u64
                && capture.selection_managed_policy_version
                    == u64::try_from(selection_policy_version).unwrap_or(u64::MAX)
                && capture.selection_managed_policy_digest.as_slice() == selection_policy_digest
                && (1..=3).contains(&capture.selected_mode)
                && capture.target_version > 0
                && capture.command_digest.iter().any(|byte| *byte != 0)
                && capture.approval_digest.iter().any(|byte| *byte != 0)
                && capture.scope_digest.iter().any(|byte| *byte != 0)
                && capture.managed_policy_digest.iter().any(|byte| *byte != 0)
                && capture.closed_rules_digest.iter().any(|byte| *byte != 0)
                && capture.root_identity.iter().any(|byte| *byte != 0)
                && capture.stdout_limit <= 65_536
                && capture.stderr_limit <= 65_536
                && capture.max_runtime_ms > 0;
        if !valid {
            return Ok(false);
        }
    }
    Ok(true)
}
