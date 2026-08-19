#[allow(clippy::too_many_lines)]
fn read_replay_state(
    connection: &Connection,
    scope: &ReplayScopeKey,
) -> Result<Option<VerifiedReplayState>, ReplayStoreError> {
    let journal_tail = verify_event_journal(connection, scope)?;
    let row: Option<StoredReplayRow> = connection
        .query_row(
            "
            SELECT
                cursors.binding_digest,
                cursors.generation,
                cursors.applied_cursor,
                cursors.event_sequence,
                cursors.projection_revision,
                cursors.projection_digest,
                projections.binding_digest,
                projections.projection_revision,
                projections.projection_digest,
                projections.event_sequence,
                projections.payload,
                (
                    SELECT COUNT(*)
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                ),
                (
                    SELECT MIN(event_sequence)
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                ),
                (
                    SELECT MAX(event_sequence)
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                ),
                (
                    SELECT cursor
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                    ORDER BY event_sequence DESC
                    LIMIT 1
                ),
                (
                    SELECT generation
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                    ORDER BY event_sequence DESC
                    LIMIT 1
                ),
                (
                    SELECT COUNT(*)
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                      AND journal.binding_digest != ?5
                )
            FROM (SELECT 1) AS seed
            LEFT JOIN replay_cursors AS cursors
              ON cursors.runtime_authority = ?1
             AND cursors.principal = ?2
             AND cursors.lineage = ?3
             AND cursors.scope = ?4
            LEFT JOIN projections
              ON projections.runtime_authority = ?1
             AND projections.principal = ?2
             AND projections.lineage = ?3
             AND projections.scope = ?4
            WHERE cursors.scope IS NOT NULL
               OR projections.scope IS NOT NULL
               OR EXISTS (
                    SELECT 1
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
               )
            ",
            params![
                scope.runtime_authority,
                scope.principal,
                scope.lineage,
                scope.scope,
                scope.binding_digest
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        if journal_tail.is_some() {
            return Err(ReplayStoreError::NonContiguousRevision);
        }
        return Ok(None);
    };
    let (
        Some(cursor_binding),
        Some(generation),
        Some(cursor),
        Some(cursor_sequence),
        Some(cursor_revision),
        Some(cursor_projection_digest),
        Some(projection_binding),
        Some(projection_revision),
        Some(projection_digest),
        Some(projection_sequence),
        Some(payload),
        journal_count,
        journal_min_sequence,
        journal_max_sequence,
        latest_journal_cursor,
        latest_journal_generation,
        journal_binding_mismatches,
    ) = row
    else {
        return Err(ReplayStoreError::NonContiguousRevision);
    };
    if cursor_binding != scope.binding_digest
        || projection_binding != scope.binding_digest
        || cursor_binding != projection_binding
        || journal_binding_mismatches != 0
    {
        return Err(ReplayStoreError::BindingMismatch);
    }
    if !is_lower_hex_digest(&cursor_projection_digest) || !is_lower_hex_digest(&projection_digest) {
        return Err(ReplayStoreError::InvalidDigest);
    }
    if cursor_revision != projection_revision {
        return Err(ReplayStoreError::NonContiguousRevision);
    }
    if cursor_projection_digest != projection_digest {
        return Err(ReplayStoreError::ProjectionDigestMismatch);
    }
    if cursor_sequence != projection_sequence {
        return Err(ReplayStoreError::NonContiguousSequence);
    }
    let generation = u64::try_from(generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
    let event_sequence =
        u64::try_from(cursor_sequence).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
    let projection_revision =
        u64::try_from(cursor_revision).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
    let journal_count =
        u64::try_from(journal_count).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
    let valid_json: i64 =
        connection.query_row("SELECT json_valid(?1)", params![payload], |row| row.get(0))?;
    if valid_json != 1 {
        return Err(ReplayStoreError::CorruptProjectionJson);
    }
    if sha256_lower_hex(&payload) != projection_digest {
        return Err(ReplayStoreError::ProjectionDigestMismatch);
    }
    let Some(journal_tail) = journal_tail else {
        return Err(ReplayStoreError::NonContiguousSequence);
    };
    if journal_tail.event_sequence != event_sequence
        || journal_tail.cursor != cursor
        || journal_tail.generation != generation
    {
        return Err(ReplayStoreError::NonContiguousSequence);
    }
    if journal_tail.projection_revision != projection_revision {
        return Err(ReplayStoreError::NonContiguousRevision);
    }
    if journal_tail.projection_digest != projection_digest
        || journal_tail.projected_payload != payload
    {
        return Err(ReplayStoreError::ProjectionDigestMismatch);
    }
    if event_sequence == 0
        || journal_count != event_sequence
        || journal_min_sequence != Some(1)
        || journal_max_sequence != Some(cursor_sequence)
        || latest_journal_cursor.as_deref() != Some(cursor.as_str())
        || latest_journal_generation
            != Some(i64::try_from(generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?)
    {
        return Err(ReplayStoreError::NonContiguousSequence);
    }
    Ok(Some(VerifiedReplayState {
        checkpoint: ReplayCheckpoint {
            cursor,
            generation,
            event_sequence,
            projection_revision,
            projection_digest: projection_digest.clone(),
            binding_digest: cursor_binding,
        },
        projection: StoredConversationProjection {
            payload,
            revision: projection_revision,
            digest: projection_digest,
            event_sequence,
            binding_digest: projection_binding,
        },
    }))
}
