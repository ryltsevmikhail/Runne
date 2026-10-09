use std::io::Read as _;
use std::path::Path;

pub(super) fn human_admission_count(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<i64> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT COUNT(*)
           FROM taskrun_local_command_attempts a
           JOIN x2_permission_human h ON h.taskrun_id=a.taskrun_id AND h.attempt_id=a.attempt_id
           JOIN x2_permission_admission p
             ON p.taskrun_id=h.taskrun_id AND p.attempt_id=h.attempt_id
            AND p.binding_digest=h.binding_digest AND p.proof_digest=h.proof_digest
          WHERE a.taskrun_id=?1 AND p.admission_kind=2",
        [id.as_bytes().as_slice()],
        |row| row.get(0),
    )
}

pub(super) fn local_no_effect_release_facts(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<(String, bool, i64, i64, i64, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT a.state,
                a.approval_id IS NULL,
                (SELECT COUNT(*) FROM x2_permission_bindings b
                  JOIN taskrun_local_permission_routes p USING(taskrun_id)
                 WHERE b.taskrun_id=a.taskrun_id AND b.attempt_id=a.attempt_id
                   AND p.route=2 AND p.provenance=3 AND p.cutover_version=68),
                (SELECT COUNT(*) FROM taskrun_no_effect_release_receipts n
                  JOIN taskrun_assignment_occupations o
                    ON o.taskrun_id=n.taskrun_id AND o.fence=n.fence
                   AND o.attempt_id=n.attempt_id
                  JOIN events e ON e.event_id=n.failure_event_id
                 WHERE n.taskrun_id=a.taskrun_id AND n.attempt_id=a.attempt_id
                   AND o.state='released' AND o.dispatch_intent='absent'
                   AND o.release_event_id=n.failure_event_id
                   AND e.aggregate_type=1 AND e.aggregate_id=n.taskrun_id
                   AND e.sequence=n.new_version),
                (SELECT COUNT(*) FROM x2_permission_spent s WHERE s.taskrun_id=a.taskrun_id),
                (SELECT COUNT(*) FROM taskrun_dispatch_intents d WHERE d.taskrun_id=a.taskrun_id)
           FROM taskrun_local_command_attempts a WHERE a.taskrun_id=?1",
        [id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )
}

pub(super) fn local_precapture_authority_facts(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<(i64, i64, i64, i64, i64, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT (SELECT COUNT(*) FROM x2_permission_bindings WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM x2_permission_human WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM x2_permission_admission WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM x2_permission_spent WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM x2_permission_stop WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM x2_permission_terminal WHERE taskrun_id=?1)",
        [id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )
}

pub(super) fn local_precapture_claim_facts(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<bool> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM taskrun_claim_receipts c
             JOIN taskrun_assignment_occupations o
               ON o.taskrun_id=c.taskrun_id AND o.fence=c.fence AND o.attempt_id=c.attempt_id
             JOIN taskrun_local_command_attempts a ON a.taskrun_id=c.taskrun_id
             WHERE c.taskrun_id=?1 AND c.new_version>0
               AND (SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1)=1
               AND o.state='active' AND o.dispatch_intent='absent'
               AND a.state='preflight' AND a.attempt_id IS NULL
               AND a.approval_id IS NULL AND a.executable_digest IS NULL
         )",
        [id.as_bytes().as_slice()],
        |row| row.get(0),
    )
}

pub(super) fn local_permission_stop_facts(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<(i64, Option<i64>)> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT COUNT(*), MAX(s.reason)
           FROM x2_permission_stop s
           JOIN taskrun_local_command_attempts a
             ON a.taskrun_id=s.taskrun_id AND a.attempt_id=s.attempt_id
          WHERE a.taskrun_id=?1",
        [id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
}

pub(super) fn local_store_diagnostic_stage(database: &Path) -> String {
    let Some(runtime_root) = database.parent().and_then(Path::parent) else {
        return "unrecognized".to_owned();
    };
    let path = runtime_root.join(".runne-test-store-diagnostic-stage");
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return "absent".to_owned();
        }
        Err(_) => return "unrecognized".to_owned(),
    };
    let mut stage = String::new();
    if file.take(65).read_to_string(&mut stage).is_err() || stage.len() > 64 {
        return "unrecognized".to_owned();
    }
    let stage = stage.strip_suffix('\n').unwrap_or(&stage);
    match stage {
        "no_effect.capture"
        | "no_effect.claim"
        | "no_effect.occupation"
        | "no_effect.runtime_evidence"
        | "no_effect.release"
        | "no_effect.mark" => stage.to_owned(),
        _ => "unrecognized".to_owned(),
    }
}

pub(super) fn durable_local_diagnostic(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> Option<String> {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    let id = uuid::Uuid::parse_str(&task.to_string()).ok()?.into_bytes();
    connection
        .query_row(
            "SELECT a.state,
                    (SELECT COUNT(*) FROM x2_permission_admission WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM x2_permission_human WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM x2_permission_spent WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM x2_permission_stop WHERE taskrun_id=?1),
                    (SELECT reason FROM x2_permission_stop WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM x2_permission_terminal WHERE taskrun_id=?1)
             FROM taskrun_local_command_attempts a WHERE a.taskrun_id=?1",
            [id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .map(|(state, admission, human, spent, stop, stop_reason, terminal)| {
            format!(
                "attempt_state={state}; admission={admission}; human={human}; spent={spent}; stop={stop}; stop_reason={stop_reason:?}; terminal={terminal}"
            )
        })
        .ok()
}
