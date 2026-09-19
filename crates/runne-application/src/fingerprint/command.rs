/// A SHA-256 fingerprint of a command's semantic payload.
///
/// Used for idempotency: two commands with the same scope, key, and
/// fingerprint are considered identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandFingerprint([u8; 32]);

impl CommandFingerprint {
    /// Create from raw 32-byte digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return a reference to the raw 32-byte digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume and return the raw 32-byte digest.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Create a fingerprint for `CreateTaskRun`.
    ///
    /// The fingerprint includes only the conversation and workspace IDs
    /// (not the server-generated `TaskRunId`).
    pub fn for_create(conversation_id: &ConversationId, workspace_id: &WorkspaceId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_CREATE]);
        // conversation_id: 16 raw bytes
        hasher.update(conversation_id.as_bytes());
        // workspace_id: 16 raw bytes
        hasher.update(workspace_id.as_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `CreateConversation`.
    pub fn for_create_conversation(
        conversation_id: &ConversationId,
        workspace_id: &WorkspaceId,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_CREATE_CONVERSATION]);
        hasher.update(conversation_id.as_bytes());
        hasher.update(workspace_id.as_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for one Conversation text execution.
    pub fn for_generate_conversation_text(
        conversation_id: &ConversationId,
        expected_version: u64,
        text: &MessageText,
    ) -> Self {
        let mut hasher = begin(TAG_GENERATE_CONVERSATION_TEXT);
        hasher.update(conversation_id.as_bytes());
        hasher.update(expected_version.to_be_bytes());
        update_string(&mut hasher, text.as_str());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for the client-authorized atomic TaskRun submit.
    ///
    /// The fingerprint includes only the conversation and workspace IDs
    /// (not the server-generated `TaskRunId`), so a lost-ack replay of the
    /// same submit identity produces the exact stored acknowledgement.
    pub fn for_submit(conversation_id: &ConversationId, workspace_id: &WorkspaceId) -> Self {
        let mut hasher = begin(TAG_SUBMIT_TASK_RUN);
        hasher.update(conversation_id.as_bytes());
        hasher.update(workspace_id.as_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `Queue`.
    pub fn for_queue(taskrun_id: &TaskRunId, expected_version: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_QUEUE]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `Admit`.
    pub fn for_admit(taskrun_id: &TaskRunId, expected_version: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_ADMIT]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for requesting TaskRun cancellation.
    pub fn for_cancel(taskrun_id: &TaskRunId, expected_version: u64) -> Self {
        let mut hasher = begin(TAG_CANCEL_TASK_RUN);
        hasher.update(taskrun_id.as_bytes());
        hasher.update(expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `StartAttempt`.
    pub fn for_start_attempt(taskrun_id: &TaskRunId, expected_version: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_START_ATTEMPT]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `Complete`.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintError::TerminalReasonTooLong`] if the
    /// `TerminalResult::Failure.reason` exceeds
    /// [`MAX_TERMINAL_REASON_BYTES`].
    pub fn for_complete(
        taskrun_id: &TaskRunId,
        result: &TerminalResult,
        expected_version: u64,
    ) -> Result<Self, FingerprintError> {
        // Validate reason length for Failure
        if let TerminalResult::Failure { reason } = result {
            let len = reason.len();
            if len > MAX_TERMINAL_REASON_BYTES {
                return Err(FingerprintError::TerminalReasonTooLong {
                    max: MAX_TERMINAL_REASON_BYTES,
                    actual: len,
                });
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_COMPLETE]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        // TerminalResult canonical encoding:
        //   tag: 0x00 = Success, 0x01 = Failure
        //   for Failure: reason_len (u16 BE) || reason_bytes
        match result {
            TerminalResult::Success => {
                hasher.update([0x00u8]);
            }
            TerminalResult::Failure { reason } => {
                hasher.update([0x01u8]);
                let reason_bytes = reason.as_bytes();
                hasher.update((reason_bytes.len() as u16).to_be_bytes());
                hasher.update(reason_bytes);
            }
        }
        Ok(Self(hasher.finalize().into()))
    }

    pub fn for_start_loop_cycle(input: &StartLoopCycleInput) -> Self {
        let mut hasher = begin(TAG_START_LOOP_CYCLE);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    pub fn for_commit_context(input: &CommitContextInput) -> Self {
        let mut hasher = begin(TAG_COMMIT_CONTEXT);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.cycle_id.as_bytes());
        update_context_ref(&mut hasher, &input.manifest_ref);
        Self(hasher.finalize().into())
    }

    pub fn for_commit_plan(input: &CommitPlanInput) -> Self {
        let mut hasher = begin(TAG_COMMIT_PLAN);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.cycle_id.as_bytes());
        update_plan_ref(&mut hasher, &input.plan_revision_ref);
        hasher.update(input.input_digest.as_bytes());
        hasher.update(input.output_digest.as_bytes());
        hasher.update((input.expected_proposal_indexes.len() as u64).to_be_bytes());
        for index in &input.expected_proposal_indexes {
            hasher.update(index.to_be_bytes());
        }
        Self(hasher.finalize().into())
    }

    pub fn for_record_step_outcome(input: &RecordStepOutcomeInput) -> Self {
        let mut hasher = begin(TAG_RECORD_STEP_OUTCOME);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.cycle_id.as_bytes());
        update_step_record(&mut hasher, &input.outcome);
        Self(hasher.finalize().into())
    }

    pub fn for_complete_loop_cycle(input: &CompleteLoopCycleInput) -> Self {
        let mut hasher = begin(TAG_COMPLETE_LOOP_CYCLE);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.cycle_id.as_bytes());
        update_disposition(&mut hasher, &input.disposition);
        Self(hasher.finalize().into())
    }

    pub fn for_create_next_cycle(input: &CreateNextCycleInput) -> Self {
        let mut hasher = begin(TAG_CREATE_NEXT_CYCLE);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.parent_cycle_id.as_bytes());
        Self(hasher.finalize().into())
    }

    pub fn for_resume_loop_wait(input: &ResumeLoopWaitInput) -> Self {
        let mut hasher = begin(TAG_RESUME_LOOP_WAIT);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        update_wake_evidence(&mut hasher, &input.wake_evidence_ref);
        Self(hasher.finalize().into())
    }

    pub fn for_schedule_retry(input: &ScheduleRetryInput) -> Self {
        let mut hasher = begin(TAG_SCHEDULE_RETRY);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.retry_ordinal.to_be_bytes());
        update_step_ref(&mut hasher, &input.step_outcome_ref);
        hasher.update(input.retry_policy_digest.as_bytes());
        update_budget_ref(&mut hasher, &input.budget_reservation_ref);
        Self(hasher.finalize().into())
    }

    pub fn for_activate_retry(input: &ActivateScheduledRetryInput) -> Self {
        let mut hasher = begin(TAG_ACTIVATE_RETRY);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.retry_ordinal.to_be_bytes());
        Self(hasher.finalize().into())
    }

    pub fn for_commit_recovery_resume(input: &CommitRecoveryResumeInput) -> Self {
        let mut hasher = begin(TAG_COMMIT_RECOVERY_RESUME);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        update_context_ref(&mut hasher, &input.context_manifest_ref);
        update_checkpoint_ref(&mut hasher, &input.checkpoint_ref);
        update_reconciliation_ref(&mut hasher, &input.reconciliation_ref);
        Self(hasher.finalize().into())
    }

    pub fn for_commit_loop_checkpoint(input: &CommitLoopCheckpointInput) -> Self {
        let mut hasher = begin(TAG_COMMIT_LOOP_CHECKPOINT);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.cycle_id.as_bytes());
        hasher.update(input.attempt_id.as_bytes());
        update_string(&mut hasher, &input.schema_version);
        match &input.plan_revision_ref {
            None => hasher.update([0]),
            Some(plan_ref) => {
                hasher.update([1]);
                update_plan_ref(&mut hasher, plan_ref);
            }
        }
        match &input.context_manifest_ref {
            None => hasher.update([0]),
            Some(context_ref) => {
                hasher.update([1]);
                update_context_ref(&mut hasher, context_ref);
            }
        }
        hasher.update((input.step_outcome_refs.len() as u64).to_be_bytes());
        for step_ref in &input.step_outcome_refs {
            update_step_ref(&mut hasher, step_ref);
        }
        Self(hasher.finalize().into())
    }
}
