fn v57_command_outcome_matches(connection: &Connection, row: &SuccessorRow) -> SqliteResult<bool> {
    use crate::codec::{CommandOutcomeCodec, StoreCodec};
    use runne_application::commands::CommandOutcome;
    use runne_domain::id::{ConversationId, TaskRunId};

    let Ok(CommandOutcome::UnknownSuccessorCreated {
        predecessor_taskrun_id,
        predecessor_version,
        conversation_id,
        conversation_version,
        successor_taskrun_id,
        successor_version,
    }) = CommandOutcomeCodec.decode(&row.command_outcome)
    else {
        return Ok(false);
    };
    let submit_position: i64 = connection.query_row(
        "SELECT global_position FROM events WHERE event_id=?1 AND aggregate_type=1
         AND aggregate_id=?2 AND sequence=?3",
        rusqlite::params![row.submit_id, row.successor, row.submit_version],
        |saved| saved.get(0),
    )?;
    let observed: Option<(Vec<u8>, i64)> = connection
        .query_row(
            "SELECT event_id,sequence FROM events WHERE aggregate_type=2 AND aggregate_id=?1
             AND global_position<?2 ORDER BY global_position DESC LIMIT 1",
            rusqlite::params![row.conversation, submit_position],
            |saved| Ok((saved.get(0)?, saved.get(1)?)),
        )
        .optional()?;
    let Some((conversation_tail, conversation_version_at_commit)) = observed else {
        return Ok(false);
    };
    let predecessor = TaskRunId::from_bytes(
        row.predecessor
            .as_slice()
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    );
    let successor = TaskRunId::from_bytes(
        row.successor
            .as_slice()
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    );
    let conversation = ConversationId::from_bytes(
        row.conversation
            .as_slice()
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    );
    Ok(predecessor_taskrun_id == predecessor
        && predecessor_version == u64::try_from(row.release_version).unwrap_or_default()
        && conversation_id == conversation
        && conversation_version
            == u64::try_from(conversation_version_at_commit).unwrap_or_default()
        && successor_taskrun_id == successor
        && successor_version == 2
        && row
            .marker_id
            .as_deref()
            .is_none_or(|marker| marker == conversation_tail)
        && row.marker_version
            == row
                .marker_id
                .as_ref()
                .map(|_| conversation_version_at_commit))
}
