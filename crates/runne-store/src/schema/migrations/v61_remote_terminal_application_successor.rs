fn v61_has_successor_generation(
    connection: &Connection,
    conversation: &[u8],
    taskrun: &[u8],
    attempt: &[u8],
    observed_event: &[u8],
    observed_version: i64,
) -> SqliteResult<bool> {
    let mut statement = connection.prepare(
        "SELECT event_id,sequence,payload FROM events
         WHERE aggregate_type=2 AND aggregate_id=?1 AND sequence<=?2 ORDER BY sequence",
    )?;
    let rows = statement.query_map(rusqlite::params![conversation, observed_version], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut original_sequence = None;
    let mut successor_sequence = None;
    let mut observed_found = false;
    for row in rows {
        let (event_id, sequence, payload) = row?;
        if sequence == observed_version && event_id.as_slice() == observed_event {
            observed_found = true;
        }
        let event = crate::codec::ConversationEventCodec
            .decode(&payload)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if let runne_domain::conversation::ConversationEvent::UserMessageAppended {
            taskrun_id,
            attempt_id,
            ..
        } = event
        {
            if taskrun_id.as_bytes() == taskrun && attempt_id.as_bytes() == attempt {
                original_sequence = Some(sequence);
            } else if original_sequence.is_some() {
                successor_sequence.get_or_insert(sequence);
            }
        }
    }
    Ok(observed_found
        && original_sequence.is_some()
        && successor_sequence.is_some_and(|sequence| sequence <= observed_version))
}
