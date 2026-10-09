use runne_application::ports::{
    RuntimeAuthorityId, TaskRunAssignmentIdentity, TaskRunNoEffectReleaseError as ReleaseError,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::{event::UncommittedEvent, id::AggregateId, task_run::TaskRunEvent};
use rusqlite::Transaction;

#[expect(
    clippy::too_many_arguments,
    reason = "the append guard receives one event and its exact transaction position and release authority"
)]
pub(crate) fn append_release_event(
    tx: &Transaction<'_>,
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<TaskRunEvent>,
    identity: &TaskRunAssignmentIdentity,
    authority: &RuntimeAuthorityId,
    current_route: bool,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
) -> Result<(), ReleaseError> {
    if !current_route {
        return crate::store::event_guard::append_taskrun_event(
            tx,
            prohibited_content,
            event,
            sequence,
            global_position,
            timestamp,
        )
        .map_err(|_| ReleaseError::CorruptData);
    }
    if !super::no_effect::marked_pre_release_matches(tx, identity, authority)
        .map_err(|_| ReleaseError::CorruptData)?
    {
        return Err(ReleaseError::DispatchMayHaveStarted);
    }
    if event.aggregate_id() != &AggregateId::TaskRun(identity.taskrun_id)
        || event.payload()
            != &(TaskRunEvent::TaskRunFailed {
                reason: "dispatch_not_started".into(),
            })
    {
        return Err(ReleaseError::CorruptData);
    }
    let (current, head): (i64, Option<Vec<u8>>) = tx
        .query_row(
            "SELECT current_version,last_event_id FROM aggregate_streams
             WHERE aggregate_type=1 AND aggregate_id=?1",
            [identity.taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| ReleaseError::CorruptData)?;
    let Some(head) = head else {
        return Err(ReleaseError::CorruptData);
    };
    if current
        .checked_add(1)
        .and_then(|next| u64::try_from(next).ok())
        != Some(sequence)
        || event
            .causation_id()
            .map(|event_id| event_id.as_bytes().as_slice())
            != Some(head.as_slice())
    {
        return Err(ReleaseError::CorruptData);
    }
    let (payload, digest, taskrun_id) = crate::store::event_guard::guard_taskrun_event(
        prohibited_content,
        event,
        sequence,
        global_position,
        timestamp,
    )
    .map_err(|_| ReleaseError::CorruptData)?;
    crate::store::append_helpers::insert_event(
        tx,
        event,
        super::super::super::CORRELATION_TYPE_TASK_RUN,
        taskrun_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
        super::super::super::INTEGRITY_PROFILE_V1,
    )
    .map_err(|_| ReleaseError::CorruptData)
}
