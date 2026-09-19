//! T1 Phase-2 wiring integration tests: the daemon root-admission gateway
//! consults the runtime-owned project trust authority before any pre-read.
//!
//! Every scenario runs on an isolated temp workspace with synthetic canaries
//! only (`RUNNE_T1_FAKE_CANARY_zq71`); grants go through the durable store
//! port, never through client flags.

#![cfg(all(unix, feature = "desktop-protected", feature = "test-support"))]

#[path = "project_trust_admission_wiring/channels.rs"]
mod channels;
#[path = "project_trust_admission_wiring/diffs_canary.rs"]
mod diffs_canary;
#[path = "project_trust_admission_wiring/harness.rs"]
mod harness;
#[path = "project_trust_admission_wiring/nm_matrix.rs"]
mod nm_matrix;
#[path = "project_trust_admission_wiring/nm_restart.rs"]
mod nm_restart;
#[path = "project_trust_admission_wiring/trust_tokens.rs"]
mod trust_tokens;

use harness::*;
use runne_api::{
    WorkspaceChangeListRequest, WorkspaceDiffReadRequest, WorkspaceFileListRequest,
    WorkspaceFileReadRequest,
};
use runne_application::project_trust::SourceChannel;

fn list(ws: runne_api::WorkspaceId, path: &str) -> runne_api::WorkspaceFileListRequest {
    WorkspaceFileListRequest::new(ws, path, 50).expect("list request")
}

fn read(ws: runne_api::WorkspaceId, path: &str) -> runne_api::WorkspaceFileReadRequest {
    WorkspaceFileReadRequest::new(ws, path).expect("read request")
}

#[test]
fn untrusted_pre_read_is_zero_content_access() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (_trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());

    let files = &fixture;
    let error = files
        .list_files(PRINCIPAL, &list(workspace(), ""))
        .expect_err("untrusted list denied");
    assert!(
        matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
        "{error:?}"
    );
    let error = files
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect_err("untrusted read denied");
    assert!(
        matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
        "{error:?}"
    );

    let diffs = &fixture;
    let error = diffs
        .list_changes(
            PRINCIPAL,
            &WorkspaceChangeListRequest::new(workspace(), 200).expect("changes"),
        )
        .expect_err("untrusted diff listing denied");
    assert!(
        matches!(error, runne_api::WorkspaceDiffHostError::Forbidden),
        "{error:?}"
    );
    let error = diffs
        .read_diff(
            PRINCIPAL,
            &WorkspaceDiffReadRequest::new(workspace(), "notes/plan.md").expect("diff"),
        )
        .expect_err("untrusted diff read denied");
    assert!(
        matches!(error, runne_api::WorkspaceDiffHostError::Forbidden),
        "{error:?}"
    );
}

#[test]
fn trusted_reads_nonsecret_file_and_lists() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    grant_trusted(&trust_store, project_trust_id(PROJECT));

    let content = fixture
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect("trusted non-secret read");
    assert!(content.content().contains(CANARY));

    let page = fixture
        .list_files(PRINCIPAL, &list(workspace(), ""))
        .expect("trusted listing");
    let paths: Vec<&str> = page
        .items()
        .iter()
        .map(|entry| entry.relative_path())
        .collect();
    assert!(paths.contains(&"README.md"), "{paths:?}");
    assert!(
        !paths.contains(&".env"),
        "frozen deny names stay hidden: {paths:?}"
    );
}

#[test]
fn frozen_sensitive_names_denied_for_trusted() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    grant_trusted(&trust_store, project_trust_id(PROJECT));

    let files = &fixture;
    for denied in [
        ".env",
        "ID_RSA",
        "keys/host.key",
        "CERT.PEM",
        "backup.p12",
        "server.ppk",
        "data.gpg",
        "credentials.json",
        ".netrc",
        ".npmrc",
        ".aws/config",
        "dir/.ssh/known_hosts",
    ] {
        let error = files
            .read_file(PRINCIPAL, &read(workspace(), denied))
            .err()
            .unwrap_or_else(|| panic!("{denied} must be denied"));
        assert!(
            matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
            "{denied}: {error:?}"
        );
    }
}

#[test]
fn managed_deny_mask_blocks_files_read_channel() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    let granted = grant_trusted(&trust_store, project_trust_id(PROJECT));

    let masked = commit_status(
        &trust_store,
        project_trust_id(PROJECT),
        runne_application::project_trust::ProjectTrustStatus::Trusted,
        SourceChannel::FilesRead.mask_bit(),
        granted.token(),
    );
    let files = &fixture;
    let error = files
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect_err("managed deny blocks the channel");
    assert!(
        matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
        "{error:?}"
    );
    files
        .list_files(PRINCIPAL, &list(workspace(), ""))
        .expect("listing channel is not masked");

    commit_status(
        &trust_store,
        project_trust_id(PROJECT),
        runne_application::project_trust::ProjectTrustStatus::Trusted,
        0,
        masked.token(),
    );
    fixture
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect("clearing the mask re-admits the channel");
}

#[test]
fn revoke_before_read_denies_content_access() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    let granted = grant_trusted(&trust_store, project_trust_id(PROJECT));
    fixture
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect("trusted read before revoke");

    commit_status(
        &trust_store,
        project_trust_id(PROJECT),
        runne_application::project_trust::ProjectTrustStatus::Untrusted,
        granted.managed_deny_mask,
        granted.token(),
    );
    let files = &fixture;
    let error = files
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect_err("revocation denies before read");
    assert!(
        matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
        "{error:?}"
    );
    let error = files
        .list_files(PRINCIPAL, &list(workspace(), ""))
        .expect_err("revocation denies listing too");
    assert!(
        matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
        "{error:?}"
    );
}

#[test]
fn symlink_escape_and_relative_paths_remain_contained() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    grant_trusted(&trust_store, project_trust_id(PROJECT));

    let outside = tempfile::tempdir().expect("outside dir");
    let outside_secret = outside.path().join("outside-secret.txt");
    std::fs::write(&outside_secret, format!("OUTSIDE {CANARY}\n")).expect("outside canary");
    std::os::unix::fs::symlink(&outside_secret, directory.path().join("leak.txt"))
        .expect("symlink");

    let error = fixture
        .read_file(PRINCIPAL, &read(workspace(), "leak.txt"))
        .expect_err("symlink escape is contained by the broker");
    assert!(!format!("{error:?}").contains(CANARY));

    assert!(matches!(
        WorkspaceFileReadRequest::new(workspace(), "a/../notes/plan.md"),
        Err(runne_api::WorkspaceFileHostError::InvalidPath)
    ));
    assert!(matches!(
        WorkspaceFileReadRequest::new(workspace(), "notes\\plan.md"),
        Err(runne_api::WorkspaceFileHostError::InvalidPath)
    ));
}
