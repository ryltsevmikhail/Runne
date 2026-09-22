//! NM-06 gap pin A (report 2026-09-19-t1 §4): conversation-scope replay
//! authorization re-enters the CURRENT durable trust revision on every
//! `current_lease` call through the production `DaemonReplayAuthorization`.
//! The check is served per call from durable state, not cached at session
//! open: a composition reopened after a serve-time trust loss denies, and a
//! re-grant re-admits without rebuilding the session. The full wire behavior
//! (401 before any SSE bytes) stays pinned by the prohibited_content_e2e
//! part_04/part_06 scenarios.

use super::nm06_delivery_gate_fixture::{
    TRUST_AUTHORITY, composition_with, reopen_gate, set_status,
};
use std::sync::{Arc, Mutex};

use crate::application::LocalSessionService;
use crate::application::replay_authorization::DaemonReplayAuthorization;
use crate::application::tests::replay_binding;
use crate::application::trust_delivery::DeliveryTrustGate;
use runne_application::ports::{ReplayAuthorizationPort, ReplayAuthorizationRequest};
use runne_application::project_trust::{ProjectTrustPersistence, ProjectTrustStatus};
use runne_domain::replay::ReplayScope;
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::ProjectTrustStore;

fn conversation_scope_request(
    conversation_id: &runne_domain::id::ConversationId,
) -> ReplayAuthorizationRequest {
    ReplayAuthorizationRequest {
        principal_id: "local-owner".to_owned(),
        authority_id: [0x77; 16],
        session_generation: 7,
        expected_epoch: 3,
        session_id: None,
        scope: Some(ReplayScope::Aggregate {
            aggregate_type: 2,
            aggregate_id: *conversation_id.as_bytes(),
        }),
    }
}

fn open_authority(db_path: &std::path::Path) -> Arc<ProjectTrustPolicyAuthority> {
    let sidecar = Arc::new(ProjectTrustStore::open(db_path, TRUST_AUTHORITY).unwrap());
    let persistence: Arc<dyn ProjectTrustPersistence> = sidecar;
    Arc::new(ProjectTrustPolicyAuthority::new(persistence))
}

#[test]
fn nm06_replay_authorization_resolves_trust_per_call_not_per_session() {
    let composed = composition_with(
        runne_domain::conversation::ConversationContextScope::Workspace,
        true,
    );
    let conversation_id = composed.conversation_id;
    set_status(&composed.sidecar, ProjectTrustStatus::Trusted);

    let local_session = Arc::new(Mutex::new(LocalSessionService::new(
        replay_binding(),
        [0x88; 32],
    )));
    let authorization = DaemonReplayAuthorization::new(
        [0x77; 16],
        Arc::clone(&local_session),
        Some(DeliveryTrustGate::open(
            open_authority(&composed.db_path),
            &composed.store,
        )),
    );
    let request = conversation_scope_request(&conversation_id);
    authorization
        .current_lease(&request)
        .expect("trusted revision admits conversation-scope delivery");

    // Trust loss between deliveries: the SAME authorization (the session was
    // opened while trusted) denies the next scope re-check.
    set_status(&composed.sidecar, ProjectTrustStatus::Untrusted);
    assert!(
        authorization.current_lease(&request).is_err(),
        "revoked revision must deny the already-opened session's next delivery"
    );

    // Serve-time reopen over the same durable state (daemon restart path):
    // the fresh composition sees the revoked revision without any replay of
    // session state.
    drop(authorization);
    drop(composed.store);
    drop(composed.sidecar);
    let (_reopened_store, reopened_gate) = reopen_gate(&composed.db_path);
    let reopened_authorization = DaemonReplayAuthorization::new(
        [0x77; 16],
        Arc::clone(&local_session),
        Some(reopened_gate_gate(reopened_gate)),
    );
    assert!(
        reopened_authorization.current_lease(&request).is_err(),
        "reopened composition must deny the revoked revision"
    );

    // Re-grant through the same durable sidecar re-admits delivery.
    let sidecar = ProjectTrustStore::open(&composed.db_path, TRUST_AUTHORITY).unwrap();
    set_status(&sidecar, ProjectTrustStatus::Trusted);
    reopened_authorization
        .current_lease(&request)
        .expect("re-grant re-admits through the fresh composition");
}

fn reopened_gate_gate(gate: DeliveryTrustGate) -> DeliveryTrustGate {
    gate
}
