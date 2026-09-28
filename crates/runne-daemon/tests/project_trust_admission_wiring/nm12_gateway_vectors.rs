//! NM-12 frozen revision-two deny-set vectors through the admitted daemon
//! file gateway, including positive non-denied controls.

use super::harness::*;
use super::read;
use runne_api::{WorkspaceFileHostError, WorkspaceFileListRequest, WorkspaceFileReadRequest};

const DENIED: &[&str] = &[
    ".git",
    "nested/.git/HEAD",
    ".ssh/config",
    ".aws/config",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".netrc",
    ".npmrc",
    ".git-credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ed25519_sk",
    "credentials.json",
    "keys/host.key",
    "keys/host.pem",
    "keys/host.p12",
    "keys/host.ppk",
    "keys/host.gpg",
    ".ENV",
    ".Git/config",
    "ID_RSA",
    "ıd_rsa",
    "id_rſa",
    "host.Key",
    "KELVIN-.key",
    "deep/nested/.ssh/known_hosts",
    "NFC/café/.env.local",
    "NFD/cafe\u{301}/.env.production",
];

#[test]
fn nm12_frozen_revision_two_paths_reject_read_and_list_but_allow_controls() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    grant_trusted(&trust_store, project_trust_id(PROJECT));

    for denied in DENIED {
        write_vector(&directory, denied);
        assert_forbidden_read_and_list(&fixture, denied);
    }
    for invalid in ["../escape", "/absolute", "a//b", "a/./b", "a\\b"] {
        assert!(matches!(
            WorkspaceFileReadRequest::new(workspace(), invalid),
            Err(WorkspaceFileHostError::InvalidPath)
        ));
        assert!(matches!(
            WorkspaceFileListRequest::new(workspace(), invalid, 50),
            Err(WorkspaceFileHostError::InvalidPath)
        ));
    }
    for ambiguous in [
        "trailing/host.key.",
        "trailing/id_rsa ",
        "trailing/name. /child",
    ] {
        let read_error = fixture
            .read_file(PRINCIPAL, &read(workspace(), ambiguous))
            .expect_err("trailing suffix is rejected by policy wiring");
        assert!(matches!(read_error, WorkspaceFileHostError::Forbidden));
        let request = WorkspaceFileListRequest::new(workspace(), ambiguous, 50)
            .expect("trailing suffix reaches gateway policy");
        let list_error = fixture
            .list_files(PRINCIPAL, &request)
            .expect_err("trailing suffix list is rejected by policy wiring");
        assert!(matches!(list_error, WorkspaceFileHostError::Forbidden));
    }

    let controls = [
        "identity.md",
        "environment.md",
        ".gitmodules",
        "x.key.txt",
        "İd_rsa",
        "заметки.md",
        "café.md",
        "cafe\u{301}.md",
    ];
    for control in controls {
        std::fs::write(directory.path().join(control), "safe control").expect("safe control file");
        let content = fixture
            .read_file(PRINCIPAL, &read(workspace(), control))
            .unwrap_or_else(|error| panic!("non-denied control {control:?}: {error:?}"));
        assert_eq!(content.content(), "safe control");
    }
    let listing = fixture
        .list_files(
            PRINCIPAL,
            &WorkspaceFileListRequest::new(workspace(), "", 200).expect("large root listing"),
        )
        .expect("trusted root listing");
    let names: Vec<_> = listing
        .items()
        .iter()
        .map(|item| item.relative_path())
        .collect();
    for control in controls {
        assert!(
            names.contains(&control),
            "non-denied control absent from list: {control:?}"
        );
    }
}

fn write_vector(directory: &tempfile::TempDir, relative: &str) {
    let path = directory.path().join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("frozen vector parent");
    }
    std::fs::write(path, format!("{CANARY}\n")).expect("frozen denied-path canary");
}

fn assert_forbidden_read_and_list(
    fixture: &runne_daemon::application::root_admission_authority_fixture::RootAdmissionAuthorityFixture,
    path: &str,
) {
    let error = fixture
        .read_file(PRINCIPAL, &read(workspace(), path))
        .expect_err("frozen sensitive path must deny read");
    assert!(
        matches!(error, WorkspaceFileHostError::Forbidden),
        "{path}: {error:?}"
    );
    assert!(!format!("{error:?}").contains(CANARY));
    let request = WorkspaceFileListRequest::new(workspace(), path, 50).expect("list vector path");
    let error = fixture
        .list_files(PRINCIPAL, &request)
        .expect_err("frozen sensitive path must deny list");
    assert!(
        matches!(error, WorkspaceFileHostError::Forbidden),
        "{path}: {error:?}"
    );
    assert!(!format!("{error:?}").contains(CANARY));
}
