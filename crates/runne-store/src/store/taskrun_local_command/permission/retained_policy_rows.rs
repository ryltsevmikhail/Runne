use super::{
    read::{self, LocalCommandPermissionCaptureV1},
    retained_context::{
        CaptureContextRowV1, OriginalCaptureContextV1, validate_optional_context_pair,
    },
};
use runne_application::ports::EventStoreError;
use runne_domain::id::TaskRunId;
use rusqlite::Connection;

pub(super) fn load(
    connection: &Connection,
    taskrun: TaskRunId,
) -> Result<
    (
        LocalCommandPermissionCaptureV1,
        Option<OriginalCaptureContextV1>,
    ),
    EventStoreError,
> {
    let capture =
        read::load_on_connection(connection, taskrun)?.ok_or(EventStoreError::CorruptData)?;
    type ContextRow = (i64, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);
    let (version, managed_digest, bytes, digest): ContextRow = connection
        .query_row(
            "SELECT selection_managed_policy_version,selection_managed_policy_digest,
                retained_context,retained_context_digest
         FROM x2_permission_bindings WHERE taskrun_id=?1 AND binding_digest=?2",
            rusqlite::params![taskrun.as_bytes(), capture.binding_digest.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let row = CaptureContextRowV1 {
        taskrun_id: *taskrun.as_bytes(),
        attempt_id: *capture.attempt_id.as_bytes(),
        invocation_id: *capture.invocation_id.as_bytes(),
        fence: capture.fence,
        binding_digest: capture.binding_digest,
        native_owner_id: capture.native_owner_id,
        native_owner_generation: capture.native_owner_generation,
        selection_managed_policy_version: u64::try_from(version)
            .map_err(|_| EventStoreError::CorruptData)?,
        selection_managed_policy_digest: managed_digest
            .try_into()
            .map_err(|_| EventStoreError::CorruptData)?,
    };
    let context = validate_optional_context_pair(
        bytes.as_deref(),
        digest.as_deref(),
        &capture.binding,
        &capture.binding_digest,
        &row,
    )
    .map_err(|_| EventStoreError::CorruptData)?;
    Ok((capture, context))
}
