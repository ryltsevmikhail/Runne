//! Closed authoritative aggregate projections used only by durable replay recovery.

mod integrity;
pub(crate) mod legacy;
mod replay;
#[cfg(test)]
mod tests;

use runne_api::{UnauthenticatedReplayProjectionV1, UnauthenticatedReplayPromotionProjectionV1};
use rusqlite::{OptionalExtension, Transaction, params};

use super::parse_helpers::storage_failure;
use super::*;
use integrity::snapshot_integrity_digest;

pub(crate) struct StoredReplayProjection {
    pub(crate) projection: UnauthenticatedReplayProjectionV1,
    #[allow(
        dead_code,
        reason = "the Task 11 baseline candidate consumes this crate-private promotion adapter"
    )]
    pub(crate) promotion_projection: UnauthenticatedReplayPromotionProjectionV1,
    pub(crate) promotion_projection_bytes: Vec<u8>,
    pub(crate) aggregate_version: u64,
    pub(crate) event_sequence: u64,
    pub(crate) head_event_id: EventId,
    pub(crate) head_integrity_digest: IntegrityDigest,
    pub(crate) head_global_position: i64,
}

pub(crate) fn backfill_all_aggregate_snapshots(
    transaction: &Transaction<'_>,
) -> rusqlite::Result<()> {
    let streams = transaction
        .prepare("SELECT aggregate_type, aggregate_id FROM aggregate_streams ORDER BY aggregate_type, aggregate_id")?
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (aggregate_type, aggregate_id) in streams {
        let aggregate_id: [u8; 16] = aggregate_id
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        refresh_aggregate_snapshot(transaction, aggregate_type, &aggregate_id)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
    }
    Ok(())
}

pub(crate) fn refresh_aggregate_snapshot(
    transaction: &Transaction<'_>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
) -> Result<(), CommitError> {
    let snapshot = replay::build_snapshot(transaction, aggregate_type, aggregate_id)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let snapshot_integrity_digest = snapshot_integrity_digest(
        aggregate_type,
        aggregate_id,
        snapshot.version,
        snapshot.version,
        snapshot.head_event_id.as_bytes(),
        snapshot.head_integrity_digest.as_bytes(),
        snapshot.head_global_position,
        snapshot.projection.projection_digest(),
        snapshot.projection.encoded_bytes(),
        &snapshot.promotion_projection_digest,
        &snapshot.promotion_projection_bytes,
    )
    .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    transaction
        .execute(
            "INSERT INTO aggregate_state_snapshots
         (aggregate_type, aggregate_id, codec_version, aggregate_version, event_sequence,
          head_event_id, head_integrity_digest, projection_bytes, projection_digest,
          promotion_codec_version, promotion_projection_bytes, promotion_projection_digest,
          head_global_position, snapshot_integrity_digest)
         VALUES (?1, ?2, 1, ?3, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?11)
         ON CONFLICT(aggregate_type, aggregate_id) DO UPDATE SET
             codec_version = excluded.codec_version,
             aggregate_version = excluded.aggregate_version,
             event_sequence = excluded.event_sequence,
             head_event_id = excluded.head_event_id,
             head_integrity_digest = excluded.head_integrity_digest,
             projection_bytes = excluded.projection_bytes,
             projection_digest = excluded.projection_digest,
             promotion_codec_version = excluded.promotion_codec_version,
             promotion_projection_bytes = excluded.promotion_projection_bytes,
             promotion_projection_digest = excluded.promotion_projection_digest,
             head_global_position = excluded.head_global_position,
             snapshot_integrity_digest = excluded.snapshot_integrity_digest",
            params![
                aggregate_type,
                aggregate_id,
                snapshot.version as i64,
                snapshot.head_event_id.as_bytes(),
                snapshot.head_integrity_digest.as_bytes(),
                snapshot.projection.encoded_bytes(),
                snapshot.projection.projection_digest().as_slice(),
                snapshot.promotion_projection_bytes,
                snapshot.promotion_projection_digest.as_slice(),
                snapshot.head_global_position,
                snapshot_integrity_digest,
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(())
}

pub(crate) fn refresh_conversation_snapshot(
    transaction: &Transaction<'_>,
    conversation_id: runne_domain::id::ConversationId,
) -> Result<(), CommitError> {
    refresh_aggregate_snapshot(
        transaction,
        CORRELATION_TYPE_CONVERSATION,
        conversation_id.as_bytes(),
    )
}

#[allow(
    dead_code,
    reason = "Task 10 replay-gap binding consumes this transaction-scoped helper"
)]
pub(crate) fn load_unauthenticated_replay_projection(
    transaction: &Transaction<'_>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
) -> Result<StoredReplayProjection, CommitError> {
    let row = transaction
        .query_row(
            "SELECT aggregate_version, event_sequence, head_event_id, head_integrity_digest,
                projection_bytes, projection_digest, promotion_codec_version,
                promotion_projection_bytes, promotion_projection_digest, head_global_position,
                snapshot_integrity_digest
         FROM aggregate_state_snapshots WHERE aggregate_type = ?1 AND aggregate_id = ?2",
            params![aggregate_type, aggregate_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let snapshot = replay::parse_stored_projection(aggregate_type, aggregate_id, row)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let binds = replay::current_head_matches(
        transaction,
        aggregate_type,
        aggregate_id,
        snapshot.aggregate_version,
        &snapshot.head_event_id,
        &snapshot.head_integrity_digest,
        snapshot.head_global_position,
    )
    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !binds {
        return Err(storage_failure(StorageFailureKind::CorruptData));
    }
    Ok(snapshot)
}

pub(crate) fn validate_all_replay_snapshots(
    connection: &rusqlite::Connection,
) -> rusqlite::Result<()> {
    let supported: i64 = connection.query_row(
        "SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type IN (1, 2)",
        [],
        |row| row.get(0),
    )?;
    let snapshots: i64 = connection.query_row(
        "SELECT COUNT(*) FROM aggregate_state_snapshots",
        [],
        |row| row.get(0),
    )?;
    let missing: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM aggregate_streams AS stream LEFT JOIN aggregate_state_snapshots AS snapshot
         ON snapshot.aggregate_type = stream.aggregate_type AND snapshot.aggregate_id = stream.aggregate_id
         WHERE stream.aggregate_type IN (1, 2) AND snapshot.aggregate_id IS NULL)", [], |row| row.get(0),
    )?;
    if supported != snapshots || missing {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let rows = connection
        .prepare(
            "SELECT aggregate_type, aggregate_id, aggregate_version, event_sequence,
                head_event_id, head_integrity_digest, projection_bytes, projection_digest,
                promotion_codec_version, promotion_projection_bytes, promotion_projection_digest,
                head_global_position, snapshot_integrity_digest FROM aggregate_state_snapshots",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                (
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (kind, id, row) in rows {
        let id: [u8; 16] = id.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let projection = replay::parse_stored_projection(kind, &id, row)?;
        if projection.event_sequence != projection.aggregate_version
            || projection.projection.aggregate_id() != id
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let transaction = connection.unchecked_transaction()?;
        let binds = replay::current_head_matches(
            &transaction,
            kind,
            &id,
            projection.aggregate_version,
            &projection.head_event_id,
            &projection.head_integrity_digest,
            projection.head_global_position,
        )?;
        transaction.rollback()?;
        if !binds {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    Ok(())
}
