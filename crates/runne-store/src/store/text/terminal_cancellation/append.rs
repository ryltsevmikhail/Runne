use super::*;

impl StoreTransaction {
    pub(super) fn append_cancellation_events(
        &self,
        tx: &rusqlite::Transaction<'_>,
        payload: &RejectTextGenerationAfterCancellationCommit,
        stored: &TextGenerationReceipt,
        cancellation_taskrun_version: u64,
        position: i64,
        now: i64,
    ) -> Result<(), CommitError> {
        let next_position = position
            .checked_add(2)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        diagnostics::on_error(
            "cancel.d2.guard_conversation",
            guard_conversation_event(
                self.prohibited_content.as_ref(),
                &payload.conversation_events[0],
                payload.receipt.conversation_version,
                position,
                now,
            ),
        )?;
        let taskrun_position = position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        diagnostics::on_error(
            "cancel.d2.guard_taskrun",
            guard_taskrun_event(
                self.prohibited_content.as_ref(),
                &payload.taskrun_events[0],
                payload.receipt.taskrun_version,
                taskrun_position,
                now,
            ),
        )?;
        diagnostics::on_error(
            "cancel.d2.append_conversation",
            append_conversation_event(
                tx,
                self.prohibited_content.as_ref(),
                &payload.conversation_events[0],
                payload.receipt.conversation_version,
                position,
                now,
            ),
        )?;
        diagnostics::on_error(
            "cancel.d2.append_taskrun",
            append_taskrun_event(
                tx,
                self.prohibited_content.as_ref(),
                &payload.taskrun_events[0],
                payload.receipt.taskrun_version,
                taskrun_position,
                now,
            ),
        )?;
        diagnostics::on_error(
            "cancel.d2.retire_occupation",
            crate::store::text::terminal_cancellation_validation::retire_cancellation_occupation(
                tx, payload,
            ),
        )?;
        diagnostics::on_error(
            "cancel.d2.head_conversation",
            update_stream_head(
                tx,
                CORRELATION_TYPE_CONVERSATION,
                stored.conversation_id.as_bytes(),
                payload.expected_conversation_version,
                payload.receipt.conversation_version,
                *payload.conversation_events[0].event_id(),
                now,
            ),
        )?;
        diagnostics::on_error(
            "cancel.d2.head_taskrun",
            update_stream_head(
                tx,
                CORRELATION_TYPE_TASK_RUN,
                stored.taskrun_id.as_bytes(),
                cancellation_taskrun_version,
                payload.receipt.taskrun_version,
                *payload.taskrun_events[0].event_id(),
                now,
            ),
        )?;
        diagnostics::on_error(
            "cancel.d2.snapshot_conversation",
            crate::store::snapshot::refresh_aggregate_snapshot(
                tx,
                CORRELATION_TYPE_CONVERSATION,
                stored.conversation_id.as_bytes(),
            ),
        )?;
        diagnostics::on_error(
            "cancel.d2.snapshot_taskrun",
            crate::store::snapshot::refresh_aggregate_snapshot(
                tx,
                CORRELATION_TYPE_TASK_RUN,
                stored.taskrun_id.as_bytes(),
            ),
        )?;
        diagnostics::on_error(
            "cancel.d2.global_position",
            update_global_position(tx, next_position),
        )?;
        Ok(())
    }
}
