//! Durable scope arbitration for create-conversation receipt duplicates.
//!
//! The create-conversation semantic fingerprint binds the delivery-context
//! scope (fingerprint format v2). Receipts stored by older builds used the
//! scope-less legacy format, so fingerprint equality alone cannot arbitrate
//! replays of those rows. Two gates decide a duplicate, and BOTH must pass:
//! the attempted fingerprint must be an explicitly supported encoding of the
//! passed identity (v2 over the passed IDs+scope, or legacy over the same
//! IDs — an arbitrary digest never yields a duplicate), and the durable
//! `conversation_context_scope` marker — written in the SAME transaction as
//! the receipt — is the authority: when it exists it must agree with the
//! attempted scope, and when it is missing (pre-V40 receipt) the exact replay
//! stays a duplicate and no scope is ever derived from the absence: the NM-06
//! delivery gate keeps unknown provenance denied regardless.

use super::super::parse_helpers::*;
use super::super::*;
use runne_domain::id::WorkspaceId;

/// Reads the durable delivery-context marker. `Ok(None)` is unknown
/// provenance, never an implicit grant; an unparsable marker is corruption.
pub(super) fn durable_context_scope(
    conn: &Connection,
    conversation_id: ConversationId,
) -> Result<Option<runne_domain::conversation::ConversationContextScope>, CommitError> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT context_scope FROM conversation_context_scope
             WHERE conversation_id = ?1",
            params![conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_commit_read_error)?;
    stored
        .map(|stored| {
            runne_domain::conversation::ConversationContextScope::parse(&stored)
                .ok_or_else(|| storage_failure(StorageFailureKind::CorruptData))
        })
        .transpose()
}

/// Extracts the `(conversation_id, workspace_id)` pair that every
/// create-conversation idempotency scope must carry.
pub(super) fn new_conversation_ids(
    idempotency_scope: &IdempotencyScope,
) -> Result<(ConversationId, WorkspaceId), CommitError> {
    match &idempotency_scope.aggregate_scope {
        AggregateScope::NewConversation {
            conversation_id,
            workspace_id,
        } => Ok((*conversation_id, *workspace_id)),
        _ => Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    }
}

/// Whether the attempted fingerprint is an explicitly supported encoding of
/// the passed command identity: the current v2 format (tag 21) over the
/// passed IDs and attempted context scope, or the legacy scope-less format
/// (tag 6) over the same IDs. Any other digest — fabricated, random, or one
/// derived from different IDs/scope — is rejected BEFORE a duplicate receipt
/// can be returned, even when the stored row happens to carry the same bytes.
pub(super) fn attempted_fingerprint_supported(
    attempted_fingerprint: &CommandFingerprint,
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
    context_scope: runne_domain::conversation::ConversationContextScope,
) -> bool {
    *attempted_fingerprint
        == CommandFingerprint::for_create_conversation(
            &conversation_id,
            &workspace_id,
            context_scope,
        )
        || *attempted_fingerprint
            == CommandFingerprint::for_create_conversation_legacy(&conversation_id, &workspace_id)
}

/// Whether the stored receipt fingerprint identifies the same create command
/// as the attempted fingerprint. The attempted digest must be an explicitly
/// supported encoding (see [`attempted_fingerprint_supported`]); given that,
/// this accepts exact-format equality plus the legacy scope-less digest of
/// the same conversation/workspace — an exact replay of a receipt committed
/// by an older build must not become a false conflict after the fingerprint
/// format gained the scope field. Scope agreement itself is arbitrated by
/// [`durable_context_scope`].
pub(super) fn stored_fingerprint_matches(
    stored_fingerprint: &CommandFingerprint,
    attempted_fingerprint: &CommandFingerprint,
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
    context_scope: runne_domain::conversation::ConversationContextScope,
) -> bool {
    attempted_fingerprint_supported(
        attempted_fingerprint,
        conversation_id,
        workspace_id,
        context_scope,
    ) && (*stored_fingerprint == *attempted_fingerprint
        || *stored_fingerprint
            == CommandFingerprint::for_create_conversation_legacy(&conversation_id, &workspace_id))
}

/// Whether the durable marker agrees with the attempted delivery-context
/// scope. A missing marker (pre-V40 receipt) cannot contradict anything and
/// keeps the historical duplicate outcome.
pub(super) fn marker_agrees_with_scope(
    conn: &Connection,
    conversation_id: ConversationId,
    attempted_scope: runne_domain::conversation::ConversationContextScope,
) -> Result<bool, CommitError> {
    Ok(
        durable_context_scope(conn, conversation_id)?
            .is_none_or(|marker| marker == attempted_scope),
    )
}
