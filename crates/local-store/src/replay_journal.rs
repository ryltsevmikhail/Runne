#[allow(clippy::too_many_lines)]
fn verify_event_journal(
    connection: &Connection,
    scope: &ReplayScopeKey,
) -> Result<Option<VerifiedJournalTail>, ReplayStoreError> {
    let mut statement = connection.prepare(
        "
        SELECT
            binding_digest,
            cursor,
            generation,
            event_sequence,
            validated_event,
            event_digest,
            projection_revision,
            projection_digest,
            projected_payload,
            json_valid(projected_payload)
        FROM event_journal
        WHERE runtime_authority = ?1
          AND principal = ?2
          AND lineage = ?3
          AND scope = ?4
        ORDER BY event_sequence
        ",
    )?;
    let mut rows = statement.query(params![
        scope.runtime_authority,
        scope.principal,
        scope.lineage,
        scope.scope
    ])?;
    let mut expected_sequence = 1_u64;
    let mut tail: Option<VerifiedJournalTail> = None;
    while let Some(row) = rows.next()? {
        let binding_digest: String = row.get(0)?;
        let cursor: String = row.get(1)?;
        let generation: i64 = row.get(2)?;
        let event_sequence: i64 = row.get(3)?;
        let validated_event: Vec<u8> = row.get(4)?;
        let event_digest: String = row.get(5)?;
        let projection_revision: i64 = row.get(6)?;
        let projection_digest: String = row.get(7)?;
        let projected_payload: Vec<u8> = row.get(8)?;
        let valid_projected_json: i64 = row.get(9)?;

        if binding_digest != scope.binding_digest {
            return Err(ReplayStoreError::BindingMismatch);
        }
        if cursor.is_empty() {
            return Err(ReplayStoreError::CursorMismatch);
        }
        let generation =
            u64::try_from(generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        let event_sequence =
            u64::try_from(event_sequence).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        let projection_revision =
            u64::try_from(projection_revision).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        if event_sequence != expected_sequence {
            return Err(ReplayStoreError::NonContiguousSequence);
        }
        if !is_lower_hex_digest(&event_digest) || !is_lower_hex_digest(&projection_digest) {
            return Err(ReplayStoreError::InvalidDigest);
        }
        if sha256_lower_hex(&validated_event) != event_digest {
            return Err(ReplayStoreError::EventDigestMismatch);
        }
        if valid_projected_json != 1 {
            return Err(ReplayStoreError::CorruptProjectionJson);
        }
        if sha256_lower_hex(&projected_payload) != projection_digest {
            return Err(ReplayStoreError::ProjectionDigestMismatch);
        }
        if let Some(previous) = tail.as_ref() {
            if projection_revision == previous.projection_revision {
                if projection_digest != previous.projection_digest
                    || projected_payload != previous.projected_payload
                {
                    return Err(ReplayStoreError::NonContiguousRevision);
                }
            } else if previous.projection_revision.checked_add(1) != Some(projection_revision) {
                return Err(ReplayStoreError::NonContiguousRevision);
            }
        } else if projection_revision > 1 {
            return Err(ReplayStoreError::NonContiguousRevision);
        }

        tail = Some(VerifiedJournalTail {
            cursor,
            generation,
            event_sequence,
            projection_revision,
            projection_digest,
            projected_payload,
        });
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(ReplayStoreError::IntegerOutOfRange)?;
    }
    Ok(tail)
}
