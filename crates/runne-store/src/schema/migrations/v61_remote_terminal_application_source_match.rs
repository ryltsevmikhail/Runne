pub(crate) fn v61_remote_application_matches_for_source(
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
    let row: Option<V61ApplicationRow> = connection
        .query_row(
            "SELECT dispatch_attempt_id,taskrun_id,taskrun_attempt_id,conversation_id,
                    generation_id,begin_command_id,request_digest,response_id_digest,artifact_digest,
                    terminal_status,publication_disposition,failure_reason,accounting_state,
                    accounting_digest,taskrun_terminal_event_id,taskrun_terminal_version,
                    conversation_terminal_event_id,conversation_terminal_version,
                    conversation_observed_event_id,conversation_observed_version,application_digest
             FROM provider_remote_terminal_applications
             WHERE dispatch_attempt_id=?1 AND taskrun_id=?2 AND taskrun_attempt_id=?3
               AND request_digest=?4 AND response_id_digest=?5 AND artifact_digest=?6
               AND terminal_status=?7",
            rusqlite::params![dispatch, taskrun, attempt, request, response, artifact, status],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                    row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?, row.get(14)?,
                    row.get(15)?, row.get(16)?, row.get(17)?, row.get(18)?, row.get(19)?,
                    row.get(20)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(false);
    };
    v61_application_row_matches(connection, &row)
}
