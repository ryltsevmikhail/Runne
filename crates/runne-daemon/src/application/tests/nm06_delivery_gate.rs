//! NM-06 delivery-gate regression scenarios. Provenance contract (T1 policy
//! revision 2): every conversation carries a durable context marker recorded
//! in the creation transaction. The former absence-based allows are gone: an
//! unregistered workspace denies (R-9 removed) and a missing/lost trust
//! record denies (R-11 removed).

use super::nm06_delivery_gate_fixture::{
    Composed, composition_with, delete_trust_rows, delete_workspace, reopen_gate, set_status,
};

use crate::application::trust_delivery::DeliveryTrustGate;
use runne_application::project_trust::ProjectTrustStatus;
use runne_domain::conversation::ConversationContextScope;
use runne_domain::id::ConversationId;

#[test]
fn nm06_delivery_gate_revision_revoke_and_storage_semantics() {
    let Composed {
        directory: _directory,
        db_path,
        gate,
        sidecar,
        store,
        conversation_id,
    } = composition_with(ConversationContextScope::Workspace, true);

    // 1. Workspace-scoped conversation, never-governed project: unknown
    //    provenance without a trust record => DENY (R-11 removed).
    assert!(
        gate.ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );

    // 2. Explicit UNTRUSTED record: governed and denied.
    set_status(&sidecar, ProjectTrustStatus::Untrusted);
    assert!(
        gate.ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );

    // 3. Grant => allow. 4. Revoke => deny (revision change between
    //    deliveries is honored in both directions). 5. Re-grant => allow.
    set_status(&sidecar, ProjectTrustStatus::Trusted);
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("trusted project admits");
    set_status(&sidecar, ProjectTrustStatus::Untrusted);
    assert!(
        gate.ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );
    set_status(&sidecar, ProjectTrustStatus::Trusted);
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("re-grant admits again");

    // 9. Closed gate (authority lost): fail closed.
    let closed = DeliveryTrustGate::closed();
    assert!(
        closed
            .ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );

    // 10. Confirmed absence (unknown conversation): allow — there is no
    //     captured material; the upstream store answers empty/404.
    let unknown: ConversationId = "018f2e3a-7000-7000-8000-0000000000e9".parse().unwrap();
    gate.ensure_conversation_trusted("local-owner", unknown)
        .expect("confirmed absence admits (nothing to deliver)");

    // 6. grant -> revoke -> trust-record disappearance: the stream still
    //    replays, but the explicit record is gone => DENY (fail-closed), and
    //    the same durable state stays denied after a restart. The restarted
    //    store owns the database exclusively, so the live handles drop first.
    set_status(&sidecar, ProjectTrustStatus::Untrusted);
    delete_trust_rows(&db_path);
    assert!(
        gate.ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );
    drop(gate);
    drop(sidecar);
    drop(store);
    let (_reopened_store, reopened_gate) = reopen_gate(&db_path);
    assert!(
        reopened_gate
            .ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );
}

#[test]
fn nm06_delivery_gate_workspace_disappearance_denies() {
    let Composed {
        directory: _directory,
        db_path,
        gate,
        sidecar,
        store,
        conversation_id,
    } = composition_with(ConversationContextScope::Workspace, true);

    // grant => allow.
    set_status(&sidecar, ProjectTrustStatus::Trusted);
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("trusted project admits");

    // grant -> revoke -> workspace disappearance: unknown ownership =>
    // DENY (R-9 removed), also across a restart.
    set_status(&sidecar, ProjectTrustStatus::Untrusted);
    delete_workspace(&db_path);
    assert!(
        gate.ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );
    drop(gate);
    drop(sidecar);
    drop(store);
    let (_reopened_store, reopened_gate) = reopen_gate(&db_path);
    assert!(
        reopened_gate
            .ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );
}

#[test]
fn nm06_delivery_gate_corruption_blocks_delivery() {
    let Composed {
        directory: _directory,
        db_path,
        gate,
        sidecar,
        store: _store,
        conversation_id,
    } = composition_with(ConversationContextScope::Workspace, true);
    set_status(&sidecar, ProjectTrustStatus::Trusted);

    // 8. Storage error (durable event corrupted, header still consistent):
    //    a read failure must BLOCK delivery instead of being treated as an
    //    absent aggregate.
    let corrupted = {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("UPDATE events SET payload = X'00' WHERE sequence = 1", [])
            .unwrap()
    };
    assert!(corrupted > 0, "event row must exist for corruption");
    assert!(
        gate.ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );

    // The corrupted aggregate does not confirm absence for other ids.
    let unknown: ConversationId = "018f2e3a-7000-7000-8000-0000000000e9".parse().unwrap();
    gate.ensure_conversation_trusted("local-owner", unknown)
        .expect("confirmed absence still admits");
}
