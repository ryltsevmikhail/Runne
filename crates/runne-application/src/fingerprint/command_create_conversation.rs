// ── CreateConversation fingerprints ──────────────────────────────────────
//
// Split out of `command.rs` to stay within the source file length budget.
//
// Format history: receipts committed before the delivery-context scope became
// part of the semantic identity were fingerprinted with
// [`TAG_CREATE_CONVERSATION`] and no scope field. Those stored digests are
// recognized by the store (see the duplicate-receipt paths) so upgrading the
// runtime never turns an exact replay of an old receipt into a conflict.

impl CommandFingerprint {
    /// Create a fingerprint for `CreateConversation`.
    ///
    /// The security-significant [`ConversationContextScope`] is part of the
    /// semantic identity: the same command, key, and IDs with a different
    /// scope produce a different fingerprint and therefore an idempotency
    /// conflict instead of a silent duplicate.
    pub fn for_create_conversation(
        conversation_id: &ConversationId,
        workspace_id: &WorkspaceId,
        context_scope: ConversationContextScope,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_CREATE_CONVERSATION_V2]);
        hasher.update(conversation_id.as_bytes());
        hasher.update(workspace_id.as_bytes());
        update_string(&mut hasher, context_scope.as_str());
        Self(hasher.finalize().into())
    }

    /// Legacy (pre-context-scope) create-conversation digest, kept only so
    /// durable receipt checks can recognize exact replays of receipts that
    /// were committed by older builds. New commits never use this format.
    pub fn for_create_conversation_legacy(
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
}
