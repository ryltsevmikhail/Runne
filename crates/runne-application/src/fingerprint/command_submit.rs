impl CommandFingerprint {
    /// Fingerprint a client-authorized atomic TaskRun submit.
    ///
    /// The no-model encoding preserves its historical digest. Explicit model
    /// selection extends command identity so reuse of an idempotency key with
    /// a different model conflicts.
    pub fn for_submit(
        conversation_id: &ConversationId,
        workspace_id: &WorkspaceId,
        input: &runne_domain::task_run::TaskRunInput,
    ) -> Self {
        let mut hasher = begin(TAG_SUBMIT_TASK_RUN);
        hasher.update(conversation_id.as_bytes());
        hasher.update(workspace_id.as_bytes());
        update_string(&mut hasher, input.prompt());
        if let Some(model) = input.requested_model() {
            hasher.update([0x01]);
            update_string(&mut hasher, model);
        }
        if let Some(profile) = input.selected_profile() {
            hasher.update([0x02]);
            update_string(&mut hasher, profile.profile_id());
            hasher.update(profile.profile_digest());
        }
        if let Some(command) = input.local_command() {
            hasher.update([0x03]);
            hasher.update(command.intent_digest());
        }
        Self(hasher.finalize().into())
    }

    /// Reconstruct the historical promptless submit fingerprint.
    pub fn for_submit_legacy(conversation_id: &ConversationId, workspace_id: &WorkspaceId) -> Self {
        let mut hasher = begin(TAG_SUBMIT_TASK_RUN);
        hasher.update(conversation_id.as_bytes());
        hasher.update(workspace_id.as_bytes());
        Self(hasher.finalize().into())
    }
}
