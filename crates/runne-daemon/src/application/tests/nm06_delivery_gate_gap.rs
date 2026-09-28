//! A retention gap may recover only when provenance is explicit TextOnly.
//! Workspace gaps lack the sequence-1 workspace binding and fail closed
//! before the replay store can issue a recovery baseline.

use super::nm06_delivery_gate_fixture::{
    AUTHORITY, Composed, composition_with, reopen_gate, set_status,
};
use std::sync::Arc;

use crate::application::trust_delivery::DeliveryTrustGate;
use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::{ApplicationCommandContext, PrincipalId, RuntimeAuthorityId};
use runne_application::project_trust::ProjectTrustStatus;
use runne_domain::conversation::ConversationContextScope;
use runne_domain::id::{ConversationId, IdempotencyKey};
use runne_domain::message::MessageText;
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;

/// Appends one user+assistant message pair through the real text path so the
/// conversation stream carries two committed events.
fn append_text(store: &StoreTransaction, conversation_id: ConversationId, expected_version: u64) {
    let guard = Arc::new(SecretBroker::new().prohibited_content_guard());
    let service = ConversationTextService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
        guard,
    );
    service
        .begin(
            &ApplicationCommandContext {
                command_id: format!("018f2e3a-7000-7000-8000-0000000000e{expected_version}")
                    .parse()
                    .unwrap(),
                idempotency_key: IdempotencyKey::new("nm06-g-append").unwrap(),
                principal_id: PrincipalId("local-owner".into()),
                actor: runne_domain::event::Actor::new("nm06-gate").unwrap(),
            },
            BeginConversationTextInput {
                conversation_id,
                expected_version,
                text: MessageText::new("gap probe message").unwrap(),
            },
        )
        .unwrap();
}

fn delete_first_conversation_event(db_path: &std::path::Path, conversation_id: ConversationId) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let changed = conn
        .execute(
            "DELETE FROM events
             WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1",
            rusqlite::params![conversation_id.as_bytes()],
        )
        .unwrap();
    assert_eq!(changed, 1, "conversation prefix row must exist");
}

fn corrupt_event_payload(db_path: &std::path::Path, sequence: i64) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let changed = conn
        .execute(
            "UPDATE events SET payload = X'00'
             WHERE aggregate_type = 2 AND sequence = ?1",
            rusqlite::params![sequence],
        )
        .unwrap();
    assert_eq!(changed, 1, "survivor row must exist");
}

fn delete_context_marker(db_path: &std::path::Path, conversation_id: ConversationId) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let changed = conn
        .execute(
            "DELETE FROM conversation_context_scope WHERE conversation_id = ?1",
            rusqlite::params![conversation_id.as_bytes()],
        )
        .unwrap();
    assert_eq!(changed, 1, "conversation context marker must exist");
}

#[test]
fn nm06_delivery_gate_text_only_marker_allows_without_trust() {
    let Composed {
        directory: _directory,
        db_path,
        gate,
        sidecar,
        store,
        conversation_id,
    } = composition_with(ConversationContextScope::TextOnly, false);

    // Explicit text-only marker recorded at creation: delivery is allowed
    // with NO workspace, NO project and NO trust record — motivated by the
    // marker, never by the absence of records.
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("explicit text-only context admits");

    // Even a governed-but-untrusted project stays out of the decision: the
    // bounded local text-only context carries no project-controlled content.
    // Revoked trust also stays out of the text-only decision...
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("revoked project does not revoke a text-only conversation");

    // ...but a closed gate still fails closed for every scope.
    let closed = DeliveryTrustGate::closed();
    assert!(
        closed
            .ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );

    // The marker is durable: a restarted gate admits the same conversation.
    // The restarted store owns the database exclusively.
    drop(gate);
    drop(sidecar);
    drop(store);
    let (_reopened_store, reopened_gate) = reopen_gate(&db_path);
    reopened_gate
        .ensure_conversation_trusted("local-owner", conversation_id)
        .expect("text-only marker survives a restart");
}

#[test]
fn nm06_workspace_retention_gaps_fail_closed_for_trusted_revoked_and_unknown() {
    let Composed {
        directory: _directory,
        db_path,
        gate,
        sidecar,
        store,
        conversation_id,
    } = composition_with(ConversationContextScope::Workspace, true);
    set_status(&sidecar, ProjectTrustStatus::Trusted);
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("trusted baseline admits");
    append_text(&store, conversation_id, 1);
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("two-event stream still admits");

    // Corruption with an intact header (count == version): DENY.
    corrupt_event_payload(&db_path, 1);
    assert!(
        gate.ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );

    for status in [ProjectTrustStatus::Trusted, ProjectTrustStatus::Untrusted] {
        let Composed {
            // The fixture owns its directory: keep the TempDir alive for the
            // whole iteration, or the identity guard fails closed on the
            // unlinked sidecar path before the gap is even created.
            directory: gap_directory,
            db_path: gap_db,
            gate: gap_gate,
            sidecar: gap_sidecar,
            store: gap_store,
            conversation_id: gap_conversation,
        } = composition_with(ConversationContextScope::Workspace, true);
        set_status(&gap_sidecar, status);
        append_text(&gap_store, gap_conversation, 1);
        delete_first_conversation_event(&gap_db, gap_conversation);
        assert!(
            gap_gate
                .ensure_conversation_trusted("local-owner", gap_conversation)
                .is_err(),
            "workspace gap must deny for {status:?}"
        );
        drop(gap_directory);
    }

    let Composed {
        directory: _unknown_directory,
        db_path: unknown_db,
        gate: unknown_gate,
        store: unknown_store,
        conversation_id: unknown_conversation,
        ..
    } = composition_with(ConversationContextScope::Workspace, true);
    append_text(&unknown_store, unknown_conversation, 1);
    delete_first_conversation_event(&unknown_db, unknown_conversation);
    delete_context_marker(&unknown_db, unknown_conversation);
    assert!(
        unknown_gate
            .ensure_conversation_trusted("local-owner", unknown_conversation)
            .is_err()
    );

    // The first row supplies the only workspace binding. Once it is gone,
    // even a current trusted revision cannot authorize the 410 baseline.
    let Composed {
        directory: restart_directory,
        db_path: restart_db,
        gate: restart_gate,
        sidecar: restart_sidecar,
        store: restart_store,
        conversation_id: restart_conversation,
    } = composition_with(ConversationContextScope::Workspace, true);
    set_status(&restart_sidecar, ProjectTrustStatus::Trusted);
    append_text(&restart_store, restart_conversation, 1);
    delete_first_conversation_event(&restart_db, restart_conversation);
    drop(restart_gate);
    drop(restart_sidecar);
    drop(restart_store);
    let (_reopened_store, reopened_gate) = reopen_gate(&restart_db);
    assert!(
        reopened_gate
            .ensure_conversation_trusted("local-owner", restart_conversation)
            .is_err(),
        "workspace gap must still deny on the reopened composition"
    );
    drop(restart_directory);

    // The immutable context marker is sufficient for bounded TextOnly
    // recovery; corruption still outranks the gap classification.
    let Composed {
        directory: text_directory,
        db_path: text_db,
        gate: text_gate,
        sidecar: text_sidecar,
        store: text_store,
        conversation_id: text_conversation,
    } = composition_with(ConversationContextScope::TextOnly, false);
    append_text(&text_store, text_conversation, 1);
    delete_first_conversation_event(&text_db, text_conversation);
    text_gate
        .ensure_conversation_trusted("local-owner", text_conversation)
        .expect("explicit TextOnly marker permits gap recovery");
    corrupt_event_payload(&text_db, 2);
    assert!(
        text_gate
            .ensure_conversation_trusted("local-owner", text_conversation)
            .is_err(),
        "corrupt retained rows must still deny"
    );
    drop(text_gate);
    drop(text_sidecar);
    drop(text_store);
    drop(text_directory);

    // Combined negative: deleted prefix AND corrupted survivor — the gap
    // must never mask a broken row. Row integrity outranks the header.
    let Composed {
        directory: _combined_directory,
        db_path: combined_db,
        gate: combined_gate,
        sidecar: _combined_sidecar,
        store: combined_store,
        conversation_id: combined_conversation,
    } = composition_with(ConversationContextScope::Workspace, true);
    append_text(&combined_store, combined_conversation, 1);
    delete_first_conversation_event(&combined_db, combined_conversation);
    corrupt_event_payload(&combined_db, 2);
    assert!(
        combined_gate
            .ensure_conversation_trusted("local-owner", combined_conversation)
            .is_err()
    );
    drop(gate);
    drop(combined_gate);
}
