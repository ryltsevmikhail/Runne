use super::codec;
use crate::store::{LocalCommandAttemptState, StoreTransaction};
use runne_application::ports::EventStoreError;
use runne_domain::id::{AttemptId, InvocationId, TaskRunId};
use rusqlite::OptionalExtension;

/// Canonical permission capture checked against its immutable route and claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCommandPermissionCaptureV1 {
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub fence: u64,
    pub invocation_id: InvocationId,
    pub canonical_binding_digest: [u8; 32],
    pub binding_digest: [u8; 32],
    pub binding: Vec<u8>,
    pub native_owner_id: [u8; 16],
    pub native_owner_generation: u64,
    pub state: LocalCommandAttemptState,
}

type CaptureRow = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Vec<u8>,
);

impl StoreTransaction {
    /// Loads a V68 capture only when its assignment and canonical codec still match.
    pub fn load_local_command_permission_capture(
        &self,
        taskrun_id: TaskRunId,
    ) -> Result<Option<LocalCommandPermissionCaptureV1>, EventStoreError> {
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let row: Option<CaptureRow> = reader
            .query_row(
                "SELECT b.attempt_id,b.fence,b.invocation_id,b.binding_digest,b.binding,
                        b.native_owner_id,b.native_owner_generation,
                        b.selection_managed_policy_version,b.selection_managed_policy_digest,
                        a.state,a.attempt_id,a.node_id,a.node_epoch,a.fence,x.node_id
                 FROM x2_permission_bindings b
                 JOIN taskrun_local_permission_routes r ON r.taskrun_id=b.taskrun_id
                 JOIN taskrun_local_command_attempts a ON a.taskrun_id=b.taskrun_id
                 JOIN taskrun_assignments x ON x.taskrun_id=b.taskrun_id
                      AND x.attempt_id=b.attempt_id AND x.fence=b.fence
                 JOIN taskrun_claim_receipts c ON c.taskrun_id=x.taskrun_id
                      AND c.attempt_id=x.attempt_id AND c.node_id=x.node_id
                      AND c.node_epoch=x.node_epoch AND c.fence=x.fence
                 WHERE b.taskrun_id=?1 AND r.route=2 AND r.provenance=3 AND r.cutover_version=68",
                [taskrun_id.as_bytes()],
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
                    ))
                },
            )
            .optional()
            .map_err(|_| EventStoreError::CorruptData)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let record = codec::decode(&row.4).map_err(|_| EventStoreError::CorruptData)?;
        let attempt: [u8; 16] = row
            .0
            .as_slice()
            .try_into()
            .map_err(|_| EventStoreError::CorruptData)?;
        let invocation: [u8; 16] = row
            .2
            .as_slice()
            .try_into()
            .map_err(|_| EventStoreError::CorruptData)?;
        let digest: [u8; 32] = row
            .3
            .as_slice()
            .try_into()
            .map_err(|_| EventStoreError::CorruptData)?;
        let owner: [u8; 16] = row
            .5
            .as_slice()
            .try_into()
            .map_err(|_| EventStoreError::CorruptData)?;
        let generation = decode_generation(&row.6)?;
        let taskrun = *taskrun_id.as_bytes();
        let node = uuid::Uuid::from_slice(&row.14).map_err(|_| EventStoreError::CorruptData)?;
        let epoch = row.12.ok_or(EventStoreError::CorruptData)?;
        let assignment_fence = row.13.ok_or(EventStoreError::CorruptData)?;
        if !codec::digest_matches(&row.4, &digest)
            || row.1 <= 0
            || row.1 != assignment_fence
            || row.7 < 0
            || row.8.len() != 32
            || row.10.as_deref() != Some(attempt.as_slice())
            || row.11.as_deref() != Some(node.as_bytes().as_slice())
            || record.taskrun_id != taskrun
            || record.attempt_id != attempt
            || record.fence != row.1 as u64
            || record.invocation_id != invocation
            || record.native_owner_id != owner
            || record.native_owner_generation != generation
            || record.selection_managed_policy_version != row.7 as u64
            || record.selection_managed_policy_digest.as_slice() != row.8.as_slice()
            || uuid::Uuid::parse_str(&record.node_id).ok() != Some(node)
            || epoch <= 0
            || record.node_epoch != epoch as u64
        {
            return Err(EventStoreError::CorruptData);
        }
        Ok(Some(LocalCommandPermissionCaptureV1 {
            taskrun_id,
            attempt_id: AttemptId::from_bytes(attempt),
            fence: row.1 as u64,
            invocation_id: InvocationId::from_bytes(invocation),
            canonical_binding_digest: record.canonical_binding_digest,
            binding_digest: digest,
            binding: row.4,
            native_owner_id: owner,
            native_owner_generation: generation,
            state: LocalCommandAttemptState::from_sql(&row.9)?,
        }))
    }
}

fn decode_generation(bytes: &[u8]) -> Result<u64, EventStoreError> {
    let encoded: [u8; 8] = bytes.try_into().map_err(|_| EventStoreError::CorruptData)?;
    let generation = u64::from_be_bytes(encoded);
    if generation == 0 {
        return Err(EventStoreError::CorruptData);
    }
    Ok(generation)
}
