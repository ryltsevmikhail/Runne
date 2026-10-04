use super::super::super::*;
use super::super::validate::BoundSuccessor;
use crate::store::append_helpers::append_conversation_event;
use crate::store::event_guard::append_taskrun_event;
use runne_application::ports::{
    CommitError, StorageFailureKind, UnknownSuccessorCommit, UnknownSuccessorCommitResult,
};
use runne_domain::command::{ConversationCommand, SubmitTaskRun, TaskRunCommand};
use runne_domain::conversation::Conversation;
use runne_domain::event::{CommandContext, materialize_batch};
use runne_domain::task_run::TaskRun;
use rusqlite::{Transaction, params};
include!("events/helpers.rs");

pub(super) fn write_events(
    store: &StoreTransaction,
    tx: &Transaction<'_>,
    payload: &UnknownSuccessorCommit,
    bound: &BoundSuccessor,
) -> Result<UnknownSuccessorCommitResult, CommitError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CommitError::ClockFailure)?
        .as_micros();
    let now = i64::try_from(now).map_err(|_| CommitError::ClockFailure)?;
    let context = CommandContext {
        command_id: payload.command_id,
        idempotency_key: payload.idempotency_key.clone(),
        actor: payload.actor.clone(),
    };
    let predecessor = crate::store::taskrun_claim::stream_validate::verify_stream(
        tx,
        payload.predecessor_taskrun_id,
        Some(payload.expected_predecessor_version),
    )
    .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let prior_timestamp: Option<i64> = tx
        .query_row(
            "SELECT last_timestamp FROM aggregate_streams
             WHERE aggregate_type=1 AND aggregate_id=?1",
            [payload.predecessor_taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    if let Some(last) = prior_timestamp
        && now < last
    {
        return Err(CommitError::ClockRegression {
            last_timestamp: runne_domain::timestamp::Timestamp::from_unix_micros(last),
            attempted: runne_domain::timestamp::Timestamp::from_unix_micros(now),
        });
    }
    let predecessor_task =
        TaskRun::replay(&predecessor.events).map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let predecessor_tail = predecessor
        .events
        .last()
        .map(|event| *event.event_id())
        .ok_or_else(|| fail(StorageFailureKind::CorruptData))?;
    let append_predecessor = bound.release_reason == "user_supersession";
    let predecessor_events = if append_predecessor {
        let predecessor_drafts = predecessor_task
            .decide(TaskRunCommand::UserSupersedeUnknown {
                predecessor_attempt_id: bound.attempt_id,
                successor_taskrun_id: payload.successor_taskrun_id,
                acknowledgement_digest: payload.acknowledgement_digest,
            })
            .map_err(|_| fail(StorageFailureKind::PolicyDenied))?;
        materialize_batch(
            predecessor_drafts,
            &[bound.predecessor_event_id],
            Some(predecessor_tail),
            &context,
        )
        .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?
    } else {
        Vec::new()
    };
    let conversation_events = if bound.add_generation_marker {
        let last_timestamp: Option<i64> = tx
            .query_row(
                "SELECT last_timestamp FROM aggregate_streams
                 WHERE aggregate_type=2 AND aggregate_id=?1",
                [bound.conversation_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| fail(StorageFailureKind::CorruptData))?;
        if let Some(last) = last_timestamp
            && now < last
        {
            return Err(CommitError::ClockRegression {
                last_timestamp: runne_domain::timestamp::Timestamp::from_unix_micros(last),
                attempted: runne_domain::timestamp::Timestamp::from_unix_micros(now),
            });
        }
        let loaded = crate::store::conversation::load_conversation_from_connection(
            tx,
            bound.conversation_id,
        )
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
        let conversation = Conversation::replay(&loaded.events)
            .map_err(|_| fail(StorageFailureKind::CorruptData))?;
        let drafts = conversation
            .decide(ConversationCommand::SupersedeGenerationUnknown {
                taskrun_id: payload.predecessor_taskrun_id,
                attempt_id: bound.attempt_id,
                successor_taskrun_id: payload.successor_taskrun_id,
                acknowledgement_digest: payload.acknowledgement_digest,
            })
            .map_err(|_| fail(StorageFailureKind::PolicyDenied))?;
        materialize_batch(
            drafts,
            &[payload.event_ids[1]],
            bound.conversation_tail,
            &context,
        )
        .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?
    } else {
        Vec::new()
    };
    let submit_drafts = TaskRun::decide_submit_with_input(
        SubmitTaskRun {
            taskrun_id: payload.successor_taskrun_id,
            conversation_id: bound.conversation_id,
            workspace_id: bound.workspace_id,
        },
        bound.successor_input.clone(),
    )
    .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    let submit_events = materialize_batch(
        submit_drafts,
        &[payload.event_ids[2], payload.event_ids[3]],
        None,
        &context,
    )
    .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    let base_position = event_position(tx)?;
    let event_count =
        i64::try_from(predecessor_events.len() + conversation_events.len() + submit_events.len())
            .map_err(|_| CommitError::GlobalPositionExhausted)?;
    let next_global_position = base_position
        .checked_add(event_count)
        .ok_or(CommitError::GlobalPositionExhausted)?;
    let conversation_version = if bound.add_generation_marker {
        bound
            .conversation_version
            .checked_add(1)
            .ok_or_else(|| fail(StorageFailureKind::IntegrityViolation))?
    } else {
        bound.conversation_version
    };
    let mut global = base_position;
    if append_predecessor {
        let predecessor_event = predecessor_events
            .first()
            .ok_or_else(|| fail(StorageFailureKind::IntegrityViolation))?;
        append_taskrun_event(
            tx,
            store.prohibited_content.as_ref(),
            predecessor_event,
            bound.predecessor_event_version,
            global,
            now,
        )?;
        update_head(
            tx,
            1,
            payload.predecessor_taskrun_id.as_bytes(),
            i64::try_from(bound.predecessor_event_version)
                .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?,
            predecessor_event.event_id().as_bytes(),
            now,
        )?;
        global = global
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        crate::store::snapshot::refresh_aggregate_snapshot(
            tx,
            1,
            payload.predecessor_taskrun_id.as_bytes(),
        )?;
    }
    if let Some(event) = conversation_events.first() {
        append_conversation_event(
            tx,
            store.prohibited_content.as_ref(),
            event,
            conversation_version,
            global,
            now,
        )?;
        update_head(
            tx,
            2,
            bound.conversation_id.as_bytes(),
            conversation_version as i64,
            event.event_id().as_bytes(),
            now,
        )?;
        global = global
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        crate::store::snapshot::refresh_conversation_snapshot(tx, bound.conversation_id)?;
    }
    if append_predecessor {
        let node = uuid::Uuid::from_bytes(bound.node_id);
        let released = tx
            .execute(
                "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1
             WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6
               AND state='active' AND dispatch_intent='present' AND release_event_id IS NULL",
                params![
                    bound.predecessor_event_id.as_bytes(),
                    payload.predecessor_taskrun_id.as_bytes(),
                    bound.fence,
                    bound.attempt_id.as_bytes(),
                    node.as_bytes(),
                    bound.node_epoch as i64,
                ],
            )
            .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
        if released != 1 {
            return Err(fail(StorageFailureKind::PolicyDenied));
        }
    }
    tx.execute(
        "INSERT INTO aggregate_streams(aggregate_type,aggregate_id,current_version,last_event_id,last_timestamp,created_at)
         VALUES(1,?1,0,NULL,NULL,?2)",
        params![payload.successor_taskrun_id.as_bytes(), now],
    )
    .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    for (index, event) in submit_events.iter().enumerate() {
        let index = i64::try_from(index).map_err(|_| CommitError::GlobalPositionExhausted)?;
        let position = global
            .checked_add(index)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        append_taskrun_event(
            tx,
            store.prohibited_content.as_ref(),
            event,
            index as u64 + 1,
            position,
            now,
        )?;
    }
    update_head(
        tx,
        1,
        payload.successor_taskrun_id.as_bytes(),
        submit_events.len() as i64,
        submit_events.last().unwrap().event_id().as_bytes(),
        now,
    )?;
    let changed = tx
        .execute(
            "UPDATE event_log_state SET next_global_position=?1
         WHERE singleton=1 AND next_global_position=?2",
            rusqlite::params![next_global_position, base_position],
        )
        .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    if changed != 1 {
        return Err(fail(StorageFailureKind::IntegrityViolation));
    }
    crate::store::snapshot::refresh_aggregate_snapshot(
        tx,
        1,
        payload.successor_taskrun_id.as_bytes(),
    )?;
    crate::store::taskrun_local_command::insert_preflight(
        tx,
        payload.successor_taskrun_id,
        submit_events[0].payload(),
        now,
    )
    .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    Ok(UnknownSuccessorCommitResult {
        predecessor_taskrun_id: payload.predecessor_taskrun_id,
        predecessor_version: bound.predecessor_event_version,
        conversation_id: bound.conversation_id,
        conversation_version,
        successor_taskrun_id: payload.successor_taskrun_id,
        successor_version: 2,
    })
}
