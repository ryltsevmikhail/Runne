//! NM-07 restart slice: durable trust decisions survive a full process
//! shutdown and a fresh composition over the same database.

use std::sync::Arc;

use super::harness::*;
use super::read;

#[test]
fn nm07_restart_reopens_the_sidecar_and_preserves_trust_state() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    {
        let (trust_store, authority) = trust_composition(&path);
        let fixture = fixture_with_trust(&store, authority, sessions());
        bind_active_root(&fixture, &directory, workspace(), real_now());
        bind_active_root(&fixture, &directory, workspace2(), real_now());
        grant_trusted(&trust_store, project_trust_id(PROJECT));
        // Full process shutdown: every handle is gone.
        drop(fixture);
        drop(trust_store);
    }
    drop(store);

    // Fresh process: the canonical store and the sidecar reopen from disk,
    // and every durable decision survives — the granted project stays
    // trusted, the untouched one stays default-deny.
    // The daemon's clean-shutdown path hands the canonical store through the
    // sanctioned test-support writer/reader open (plain reopen after a live
    // session is the D1.3 recovery flow's territory, out of T1 scope).
    let writer = runne_store::schema::open_test_shared_writer(&path).expect("canonical writer");
    let reader = runne_store::schema::open_test_shared_writer(&path).expect("canonical reader");
    let guard: Arc<dyn runne_application::prohibited_content::ProhibitedContentPort> =
        Arc::new(runne_security::SecretBroker::new().prohibited_content_guard());
    let store = runne_store::store::StoreTransaction::open_with_connections(
        path.to_str().expect("database path"),
        writer,
        reader,
        runne_application::ports::RuntimeAuthorityId(AUTHORITY_NAME.into()),
        guard,
    )
    .expect("canonical store reopen");
    let (trust_store, authority) = trust_composition(&path);
    assert_eq!(
        load_record(&trust_store, project_trust_id(PROJECT)).status,
        runne_application::project_trust::ProjectTrustStatus::Trusted
    );
    assert_eq!(
        load_record(&trust_store, project_trust_id(PROJECT2)).status,
        runne_application::project_trust::ProjectTrustStatus::Untrusted
    );
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    bind_active_root(&fixture, &directory, workspace2(), real_now());
    fixture
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect("trust survives the restart");
    let error = fixture
        .read_file(PRINCIPAL, &read(workspace2(), "notes/plan.md"))
        .expect_err("default deny survives the restart");
    assert!(
        matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
        "{error:?}"
    );
}

#[test]
fn nm08_trust_transitions_apply_live_in_one_session() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    let granted = grant_trusted(&trust_store, project_trust_id(PROJECT));
    let files = &fixture;
    files
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect("trusted read");

    let revoked = commit_status(
        &trust_store,
        project_trust_id(PROJECT),
        runne_application::project_trust::ProjectTrustStatus::Untrusted,
        granted.managed_deny_mask,
        granted.token(),
    );
    let error = files
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect_err("downgrade denies the live session");
    assert!(
        matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
        "{error:?}"
    );

    commit_status(
        &trust_store,
        project_trust_id(PROJECT),
        runne_application::project_trust::ProjectTrustStatus::Trusted,
        0,
        revoked.token(),
    );
    files
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect("re-grant re-admits the live session without a re-bind");
}
