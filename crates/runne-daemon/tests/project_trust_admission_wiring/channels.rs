//! Editor-channel and fresh-project scoping of the trust gate.

use runne_api::{EditorLaunchTargetV1, OpenEditorRequest};

use super::harness::*;
use super::{list, read};

#[test]
fn fresh_workspace_in_ungranted_project_stays_denied() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    let now = real_now();
    bind_active_root(&fixture, &directory, workspace(), now);
    bind_active_root(&fixture, &directory, workspace2(), now);
    grant_trusted(&trust_store, project_trust_id(PROJECT));

    let files = &fixture;
    files
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect("granted project reads");
    let error = files
        .read_file(PRINCIPAL, &read(workspace2(), "notes/plan.md"))
        .expect_err("fresh project is default-deny");
    assert!(
        matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
        "{error:?}"
    );
    let error = files
        .list_files(PRINCIPAL, &list(workspace2(), ""))
        .expect_err("no auto-trust compensation for fresh projects");
    assert!(
        matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
        "{error:?}"
    );

    grant_trusted(&trust_store, project_trust_id(PROJECT2));
    fixture
        .read_file(PRINCIPAL, &read(workspace2(), "notes/plan.md"))
        .expect("explicit grant admits the fresh project");
}

#[test]
fn editor_denies_untrusted_before_launch() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (_trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());

    let request = |path: &str| {
        OpenEditorRequest::new(workspace(), path, EditorLaunchTargetV1::SystemDefault)
            .expect("editor request")
    };
    let error = fixture
        .open_editor(PRINCIPAL, &request("notes/plan.md"))
        .expect_err("editor denied for untrusted project before any launch");
    assert!(
        matches!(error, runne_api::WorkspaceEditorHostError::Forbidden),
        "{error:?}"
    );
    let error = fixture
        .open_editor(PRINCIPAL, &request(".env"))
        .expect_err("frozen deny names never reach the editor");
    assert!(
        matches!(error, runne_api::WorkspaceEditorHostError::Forbidden),
        "{error:?}"
    );
}
