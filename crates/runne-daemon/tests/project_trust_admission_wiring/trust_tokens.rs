//! Trust-token semantics against the composition authority: stale/foreign
//! tokens fail closed, sidecar recreation never resurrects old epochs, and
//! the single policy version stays observable in-process.

use std::path::PathBuf;

use runne_application::project_trust::{
    PermissionMode, SourceAdmissionRequest, SourceChannel, TrustAdmissionError,
};
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;

use super::harness::*;
use super::read;

#[test]
fn stale_revision_and_foreign_epoch_tokens_fail_closed() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority.clone(), sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    let granted = grant_trusted(&trust_store, project_trust_id(PROJECT));

    let request = |observed, mode| SourceAdmissionRequest {
        channel: SourceChannel::FilesRead,
        path: Some("notes/plan.md"),
        observed_token: observed,
        permission_mode: mode,
    };
    // The composition authority itself rejects stale/foreign tokens even under
    // the strongest permission-mode claim.
    authority
        .admit_source(project_trust_id(PROJECT), request(Some(granted.token()), PermissionMode::FullAccess))
        .expect("current token admits");

    let revoked = commit_status(
        &trust_store,
        project_trust_id(PROJECT),
        runne_application::project_trust::ProjectTrustStatus::Untrusted,
        0,
        granted.token(),
    );
    let error = authority
        .admit_source(project_trust_id(PROJECT), request(Some(granted.token()), PermissionMode::FullAccess))
        .expect_err("stale token fails closed");
    assert_eq!(
        error,
        TrustAdmissionError::StaleRevision { observed: granted.revision, current: revoked.revision }
    );
    let foreign = runne_application::project_trust::TrustToken::new(granted.instance_epoch + 1, revoked.revision);
    let error = authority
        .admit_source(project_trust_id(PROJECT), request(Some(foreign), PermissionMode::FullAccess))
        .expect_err("foreign epoch fails closed");
    assert_eq!(error, TrustAdmissionError::ForeignEpoch {
        observed_epoch: foreign.instance_epoch,
        current_epoch: revoked.instance_epoch,
    });

    let error = fixture
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect_err("gateway reads fresh durable state, not client tokens");
    assert!(matches!(error, runne_api::WorkspaceFileHostError::Forbidden), "{error:?}");
}

#[test]
fn sidecar_recreation_defaults_deny_without_resurrection() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let epoch_one = {
        let (trust_store, authority) = trust_composition(&path);
        let fixture = fixture_with_trust(&store, authority, sessions());
        bind_active_root(&fixture, &directory, workspace(), real_now());
        let granted = grant_trusted(&trust_store, project_trust_id(PROJECT));
        fixture
            .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
            .expect("trusted read in the first epoch");
        granted.token()
    };
    for suffix in ["", "-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}.project-trust", path.display()));
        let _ = std::fs::remove_file(sidecar);
    }

    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority.clone(), sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    let error = fixture
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect_err("fresh sidecar defaults to deny");
    assert!(matches!(error, runne_api::WorkspaceFileHostError::Forbidden), "{error:?}");

    let error = authority
        .admit_source(
            project_trust_id(PROJECT),
            SourceAdmissionRequest {
                channel: SourceChannel::FilesRead,
                path: Some("notes/plan.md"),
                observed_token: Some(epoch_one),
                permission_mode: PermissionMode::Ask,
            },
        )
        .expect_err("old-epoch token stays foreign after recreation");
    assert!(matches!(error, TrustAdmissionError::ForeignEpoch { .. }), "{error:?}");

    grant_trusted(&trust_store, project_trust_id(PROJECT));
    fixture
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect("a fresh grant in the new epoch admits");
}

/// The composition authority is observable in-process for token semantics.
#[test]
fn composition_authority_exposes_single_policy_version() {
    let (_directory, path, _store) = store();
    let (_trust_store, authority) = trust_composition(&path);
    let admission = authority
        .admit_source(
            project_trust_id(PROJECT),
            SourceAdmissionRequest {
                channel: SourceChannel::FilesList,
                path: None,
                observed_token: None,
                permission_mode: PermissionMode::Ask,
            },
        )
        .expect_err("absent project row is the untrusted default");
    // Fresh authority load: absent row -> untrusted default deny.
    assert!(matches!(
        admission,
        TrustAdmissionError::DeniedByPolicy {
            reason: runne_application::project_trust::SourceDenyReason::Untrusted
        }
    ), "{admission:?}");
    let _policy: &ProjectTrustPolicyAuthority = &authority;
}
