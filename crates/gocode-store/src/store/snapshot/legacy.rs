use rusqlite::{Transaction, params};

use super::{integrity::snapshot_integrity_digest_v1, replay};

/// Writes only the historical V17 schema shape for test-only construction of
/// locally-created V17 databases. Runtime upgrades target V18 directly.
pub(crate) fn backfill_v17_aggregate_snapshots(
    transaction: &Transaction<'_>,
) -> rusqlite::Result<()> {
    let streams = transaction.prepare("SELECT aggregate_type, aggregate_id FROM aggregate_streams ORDER BY aggregate_type, aggregate_id")?
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (aggregate_type, aggregate_id) in streams {
        let aggregate_id: [u8; 16] = aggregate_id
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let snapshot = replay::build_snapshot(transaction, aggregate_type, &aggregate_id)?;
        let digest = snapshot_integrity_digest_v1(
            aggregate_type,
            &aggregate_id,
            snapshot.version,
            snapshot.version,
            snapshot.head_event_id.as_bytes(),
            snapshot.head_integrity_digest.as_bytes(),
            snapshot.head_global_position,
            snapshot.projection.projection_digest(),
            snapshot.projection.encoded_bytes(),
        )
        .ok_or(rusqlite::Error::InvalidQuery)?;
        transaction.execute("INSERT INTO aggregate_state_snapshots (aggregate_type, aggregate_id, codec_version, aggregate_version, event_sequence, head_event_id, head_integrity_digest, projection_bytes, projection_digest, head_global_position, snapshot_integrity_digest) VALUES (?1, ?2, 1, ?3, ?3, ?4, ?5, ?6, ?7, ?8, ?9)", params![aggregate_type, aggregate_id, snapshot.version as i64, snapshot.head_event_id.as_bytes(), snapshot.head_integrity_digest.as_bytes(), snapshot.projection.encoded_bytes(), snapshot.projection.projection_digest().as_slice(), snapshot.head_global_position, digest])?;
    }
    Ok(())
}
