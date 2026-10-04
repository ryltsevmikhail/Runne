include!("v62_remote_terminal_audit_match_read.rs");

use crate::store::taskrun_submit_origin::{
    RemoteTerminalTaskRunApplicability, verify_remote_terminal_taskrun_source,
};

fn v62_audit_receipts_match(connection: &Connection) -> SqliteResult<bool> {
    if !v62_audit_source_finance_rows_match(connection, None)? {
        return Ok(false);
    }
    let mut statement = connection.prepare(
        "SELECT dispatch_attempt_id,taskrun_id,taskrun_attempt_id,conversation_id,
                request_digest,response_id_digest,artifact_digest,terminal_status,witness_kind,
                terminal_event_id,terminal_version,successor_taskrun_id,successor_submit_event_id,
                successor_submit_version,supersession_event_id,supersession_version,release_event_id,
                release_version,release_fence,release_reason,acknowledgement_digest,
                conversation_observed_event_id,conversation_observed_version,accounting_state,
                accounting_digest,audit_digest
         FROM provider_remote_terminal_audit_receipts",
    )?;
    let rows = statement.query_map([], read_v62_audit_row)?;
    for row in rows {
        let row = row?;
        if !v62_audit_row_matches(connection, &row)? {
            return Ok(false);
        }
    }
    Ok(true)
}

include!("v62_remote_terminal_audit_source_finance.rs");

fn v62_audit_row_matches(connection: &Connection, row: &V62AuditRow) -> SqliteResult<bool> {
    let fields = &row.fields;
    if !v62_audit_source_finance_rows_match(connection, Some(fields.dispatch.as_slice()))? {
        return Ok(false);
    }
    if fields.terminal_version.is_some_and(|value| value <= 0)
        || fields
            .successor_submit_version
            .is_some_and(|value| value <= 0)
        || fields.supersession_version.is_some_and(|value| value <= 0)
        || fields.conversation_observed_version <= 0
        || row.release_version <= 0
        || row.release_fence <= 0
        || fields.accounting_state == 1 && fields.accounting_digest.is_none()
        || fields.accounting_state == 2 && fields.accounting_digest.is_some()
    {
        return Ok(false);
    }
    let observed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM events WHERE aggregate_type=2 AND aggregate_id=?1
             AND event_id=?2 AND sequence=?3)",
        params![
            &row.conversation,
            &row.conversation_event,
            row.conversation_version
        ],
        |saved| saved.get(0),
    )?;
    if !observed {
        return Ok(false);
    }
    let authority: Vec<u8> = connection.query_row(
        "SELECT runtime_authority_id FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
        [fields.dispatch.as_slice()],
        |saved| saved.get(0),
    )?;
    let authority: [u8; 16] = match authority.as_slice().try_into() {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let authority = authority.iter().map(|byte| format!("{byte:02x}")).collect();
    let verified = verify_remote_terminal_taskrun_source(
        connection,
        &fields.dispatch,
        &runne_application::ports::RuntimeAuthorityId(authority),
    );
    let Ok(verified) = verified else {
        return Ok(false);
    };
    if verified.taskrun_id.as_bytes().as_slice() != row.taskrun.as_slice()
        || verified.taskrun_attempt_id.as_bytes().as_slice() != row.attempt.as_slice()
        || verified.conversation_id.as_bytes().as_slice() != row.conversation.as_slice()
    {
        return Ok(false);
    }
    match fields.witness_kind {
        1 => {
            let RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion {
                terminal_event_id,
                terminal_version,
                release_reason,
                ..
            } = verified.applicability
            else {
                return Ok(false);
            };
            if row.terminal_event.as_deref() != Some(terminal_event_id.as_slice())
                || row.terminal_version != i64::try_from(terminal_version).ok()
                || row.release_event.as_slice() != terminal_event_id
                || row.release_version != i64::try_from(terminal_version).unwrap_or_default()
                || row.reason != release_reason
                || row.successor.is_some()
                || row.supersession.is_some()
            {
                return Ok(false);
            }
            let release: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts r
                 JOIN taskrun_assignment_occupations o ON o.taskrun_id=r.taskrun_id
                   AND o.fence=r.fence AND o.attempt_id=r.attempt_id
                   AND o.node_id=r.node_id AND o.node_epoch=r.node_epoch
                 JOIN events e ON e.aggregate_type=1 AND e.aggregate_id=r.taskrun_id
                   AND e.event_id=r.terminal_event_id AND e.sequence=r.terminal_version
                 WHERE r.taskrun_id=?1 AND r.attempt_id=?2 AND r.terminal_event_id=?3
                   AND r.terminal_version=?4 AND r.fence=?5
                   AND o.state='released' AND o.release_event_id=r.terminal_event_id
                   )",
                params![
                    &row.taskrun,
                    &row.attempt,
                    &row.release_event,
                    row.release_version,
                    row.release_fence
                ],
                |saved| saved.get(0),
            )?;
            if !release {
                return Ok(false);
            }
        }
        2 => {
            if !v57_successor_witness_matches_for_v62_audit(
                connection,
                fields.dispatch.as_slice(),
                row.taskrun.as_slice(),
                row.attempt.as_slice(),
            )? {
                return Ok(false);
            }
            let RemoteTerminalTaskRunApplicability::ExactUserSupersession {
                successor_taskrun_id,
                release_event_id,
                release_version,
                ..
            } = verified.applicability
            else {
                return Ok(false);
            };
            if row.successor.as_deref() != Some(successor_taskrun_id.as_bytes().as_slice())
                || row.release_event.as_slice() != release_event_id
                || row.release_version != i64::try_from(release_version).unwrap_or_default()
                || row.terminal_event.is_some()
            {
                return Ok(false);
            }
            let valid: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_unknown_successor_receipts u
                 JOIN taskrun_assignment_occupations o ON o.taskrun_id=u.predecessor_taskrun_id
                   AND o.fence=u.occupation_fence AND o.attempt_id=u.predecessor_attempt_id
                 JOIN events e ON e.aggregate_type=1 AND e.aggregate_id=u.predecessor_taskrun_id
                   AND e.event_id=u.occupation_release_event_id
                   AND e.sequence=u.occupation_release_version
                 WHERE u.predecessor_taskrun_id=?1 AND u.predecessor_attempt_id=?2
                   AND u.predecessor_dispatch_attempt_id=?3 AND u.successor_taskrun_id=?4
                   AND u.successor_submit_event_id=?5 AND u.successor_submit_version=?6
                   AND u.occupation_release_event_id=?7 AND u.occupation_release_version=?8
                   AND u.occupation_fence=?9 AND u.occupation_release_reason='user_supersession'
                   AND u.acknowledgement_digest=?10 AND o.state='released'
                   AND o.release_event_id=u.occupation_release_event_id)",
                params![
                    &row.taskrun,
                    &row.attempt,
                    &fields.dispatch,
                    row.successor.as_deref(),
                    row.successor_submit.as_deref(),
                    row.successor_submit_version,
                    &row.release_event,
                    row.release_version,
                    row.release_fence,
                    row.acknowledgement.as_deref()
                ],
                |saved| saved.get(0),
            )?;
            if !valid {
                return Ok(false);
            }
        }
        _ => return Ok(false),
    }
    Ok(v62_audit_digest(fields).as_slice() == row.digest.as_slice())
}

pub(super) fn v62_valid_supersession_audit_for_attempt(
    connection: &Connection,
    dispatch: &[u8],
    taskrun: &[u8],
    attempt: &[u8],
) -> SqliteResult<bool> {
    let Some(row) = v62_read_audit_for_dispatch(connection, dispatch)? else {
        return Ok(false);
    };
    if row.fields.witness_kind != 2
        || row.fields.taskrun.as_slice() != taskrun
        || row.fields.attempt.as_slice() != attempt
    {
        return Ok(false);
    }
    v62_audit_row_matches(connection, &row)
}

pub(crate) fn v62_valid_audit_for_source(
    connection: &Connection,
    source: crate::schema::RemoteTerminalSourceMatch<'_>,
) -> SqliteResult<bool> {
    let crate::schema::RemoteTerminalSourceMatch {
        dispatch,
        taskrun,
        attempt,
        request,
        response,
        artifact,
        status,
    } = source;
    let Some(row) = v62_read_audit_for_dispatch(connection, dispatch)? else {
        return Ok(false);
    };
    if row.fields.taskrun.as_slice() != taskrun
        || row.fields.attempt.as_slice() != attempt
        || row.fields.request.as_slice() != request
        || row.fields.response.as_slice() != response
        || row.fields.artifact.as_slice() != artifact
        || row.fields.terminal_status != status
    {
        return Ok(false);
    }
    v62_audit_row_matches(connection, &row)
}

fn v62_read_audit_for_dispatch(
    connection: &Connection,
    dispatch: &[u8],
) -> SqliteResult<Option<V62AuditRow>> {
    let mut statement = connection.prepare(
        "SELECT dispatch_attempt_id,taskrun_id,taskrun_attempt_id,conversation_id,
                request_digest,response_id_digest,artifact_digest,terminal_status,witness_kind,
                terminal_event_id,terminal_version,successor_taskrun_id,successor_submit_event_id,
                successor_submit_version,supersession_event_id,supersession_version,release_event_id,
                release_version,release_fence,release_reason,acknowledgement_digest,
                conversation_observed_event_id,conversation_observed_version,accounting_state,
                accounting_digest,audit_digest
         FROM provider_remote_terminal_audit_receipts WHERE dispatch_attempt_id=?1",
    )?;
    let mut rows = statement.query_map([dispatch], read_v62_audit_row)?;
    let Some(row) = rows.next() else {
        return Ok(None);
    };
    let row = row?;
    if rows.next().transpose()?.is_some() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(Some(row))
}
