//! Diff-channel trust wiring: an unverified baseline never fabricates diffs,
//! and frozen sensitive names never leak through change listings or diff
//! reads — not even as a canary the client itself planted in `.env`.

use runne_api::{WorkspaceChangeListRequest, WorkspaceDiffReadRequest};

use super::harness::*;
use super::read;

#[test]
fn diffs_denied_until_trusted_baseline_capture() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());

    let diffs = &fixture;
    let error = diffs
        .list_changes(PRINCIPAL, &WorkspaceChangeListRequest::new(workspace(), 200).expect("changes"))
        .expect_err("diffs denied before trusted capture");
    assert!(matches!(error, runne_api::WorkspaceDiffHostError::Forbidden), "{error:?}");

    grant_trusted(&trust_store, project_trust_id(PROJECT));
    fixture
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect("files read from fresh durable state");
    let error = diffs
        .list_changes(PRINCIPAL, &WorkspaceChangeListRequest::new(workspace(), 200).expect("changes"))
        .expect_err("an unverified baseline never fabricates a plausible diff");
    assert!(matches!(error, runne_api::WorkspaceDiffHostError::Forbidden), "{error:?}");
    let error = diffs
        .read_diff(PRINCIPAL, &WorkspaceDiffReadRequest::new(workspace(), "notes/plan.md").expect("diff"))
        .expect_err("diff read stays denied until an approved capture exists");
    assert!(matches!(error, runne_api::WorkspaceDiffHostError::Forbidden), "{error:?}");

    // A re-bind while trusted performs the approved baseline capture.
    bind_active_root(&fixture, &directory, workspace(), real_now());
    std::fs::write(directory.path().join("notes/plan.md"), format!("plan changed {CANARY}\n")).expect("edit");
    let changes = diffs
        .list_changes(PRINCIPAL, &WorkspaceChangeListRequest::new(workspace(), 200).expect("changes"))
        .expect("captured baseline serves diffs");
    assert!(
        changes.entries().iter().any(|entry| entry.path() == "notes/plan.md"),
        "{:?}",
        changes.entries().iter().map(|entry| entry.path().to_owned()).collect::<Vec<_>>()
    );
    let diff = diffs
        .read_diff(PRINCIPAL, &WorkspaceDiffReadRequest::new(workspace(), "notes/plan.md").expect("diff"))
        .expect("diff read after approved capture");
    assert!(diff.hunks()[0].lines().iter().any(|line| line.text().contains(CANARY)));
}

/// Canary: while trusted, a secret planted into the frozen-deny `.env` after
/// the approved capture must stay invisible to the diff channel — the listing
/// never names the path and the diff read is Forbidden, never `NotFound`.
#[test]
fn trusted_rebind_baseline_excludes_secret_canary_from_diffs() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    grant_trusted(&trust_store, project_trust_id(PROJECT));
    bind_active_root(&fixture, &directory, workspace(), real_now());

    std::fs::write(directory.path().join(".env"), format!("TOKEN={CANARY}\n")).expect("edit secret");

    let diffs = &fixture;
    let changes = diffs
        .list_changes(PRINCIPAL, &WorkspaceChangeListRequest::new(workspace(), 200).expect("changes"))
        .expect("captured baseline serves diffs");
    assert!(
        !changes.entries().iter().any(|entry| entry.path() == ".env"),
        "frozen deny names never surface as changes: {:?}",
        changes.entries().iter().map(|entry| entry.path().to_owned()).collect::<Vec<_>>()
    );

    let error = diffs
        .read_diff(PRINCIPAL, &WorkspaceDiffReadRequest::new(workspace(), ".env").expect("diff"))
        .expect_err("frozen deny names are denied on diff reads");
    assert!(matches!(error, runne_api::WorkspaceDiffHostError::Forbidden), "{error:?}");
    assert!(!format!("{error:?}").contains(CANARY), "no canary text in the denial");
}
