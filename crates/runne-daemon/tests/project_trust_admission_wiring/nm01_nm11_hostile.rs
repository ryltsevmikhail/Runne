use runne_application::project_trust::{
    PermissionMode, SourceAdmissionRequest, SourceChannel, SourceDenyReason, TrustAdmissionError,
};

use super::harness::*;
use super::{list, read};

#[test]
fn nm01_symlink_chain_and_directory_escape_are_denied_before_content() {
    use std::os::unix::fs::symlink;

    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let outside = tempfile::tempdir().expect("outside fixture");
    std::fs::write(outside.path().join("secret.txt"), format!("{CANARY}\n"))
        .expect("outside canary");
    std::fs::create_dir_all(outside.path().join("nested")).expect("outside directory");
    std::fs::write(
        outside.path().join("nested/secret.txt"),
        format!("{CANARY}\n"),
    )
    .expect("nested outside canary");
    symlink(outside.path(), directory.path().join("first-link")).expect("first link");
    symlink("first-link", directory.path().join("second-link")).expect("link chain");
    symlink(outside.path(), directory.path().join("outside-dir")).expect("directory link");

    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority.clone(), sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    grant_trusted(&trust_store, project_trust_id(PROJECT));

    for path in [
        "second-link/secret.txt",
        "outside-dir/secret.txt",
        "outside-dir/nested/secret.txt",
    ] {
        let error = fixture
            .read_file(PRINCIPAL, &read(workspace(), path))
            .expect_err("symlink escape must not return content");
        assert!(matches!(
            error,
            runne_api::WorkspaceFileHostError::Forbidden
        ));
        assert!(!format!("{error:?}").contains(CANARY));
    }
    for path in ["second-link", "outside-dir"] {
        let error = fixture
            .list_files(PRINCIPAL, &list(workspace(), path))
            .expect_err("symlink directories must not be listed");
        assert!(matches!(
            error,
            runne_api::WorkspaceFileHostError::Forbidden
        ));
    }

    drop(fixture);
    drop(authority);
    drop(trust_store);
    drop(store);
    let scanner = super::nm10_rules::scanner(&[CANARY]);
    for suffix in [
        "",
        "-wal",
        "-shm",
        ".project-trust",
        ".project-trust-wal",
        ".project-trust-shm",
    ] {
        let mut sink_name = path.as_os_str().to_owned();
        sink_name.push(suffix);
        let sink = std::path::PathBuf::from(sink_name);
        if sink.is_file() {
            let bytes = std::fs::read(&sink).expect("read closed fixture database sink");
            super::nm10_rules::scan_absent(&scanner, "NM01 outside-canary persistence", &bytes);
        }
    }
}

#[test]
fn nm04_path_shapes_reject_traversal_and_keep_tilde_workspace_relative() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    grant_trusted(&trust_store, project_trust_id(PROJECT));

    for path in [
        "../secret",
        "./secret",
        "/etc/passwd",
        "dir//secret",
        "dir/./secret",
    ] {
        assert!(matches!(
            runne_api::WorkspaceFileReadRequest::new(workspace(), path),
            Err(runne_api::WorkspaceFileHostError::InvalidPath)
        ));
        assert!(matches!(
            runne_api::WorkspaceFileListRequest::new(workspace(), path, 10),
            Err(runne_api::WorkspaceFileHostError::InvalidPath)
        ));
    }

    // Home-prefix syntax is rejected by the source-path normalizer and never
    // expanded against a user's home directory.
    let error = fixture
        .read_file(PRINCIPAL, &read(workspace(), "~/.ssh/id_rsa"))
        .expect_err("home-prefix path stays denied");
    assert!(matches!(
        error,
        runne_api::WorkspaceFileHostError::Forbidden
    ));
    assert!(!format!("{error:?}").contains(CANARY));
}

#[test]
fn nm11_hostile_project_files_do_not_enable_unavailable_channels() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    for (name, contents) in [
        ("AGENTS.md", "synthetic instruction marker"),
        ("skills/entry.md", "synthetic skill marker"),
        ("hooks/pre.sh", "synthetic hook marker"),
        ("helpers/run.sh", "synthetic helper marker"),
        (".mcp.json", "{\"mcpServers\":{}}"),
    ] {
        let file = directory.path().join(name);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).expect("hostile channel directory");
        }
        std::fs::write(file, contents).expect("hostile channel file");
    }

    let (trust_store, authority) = trust_composition(&path);
    grant_trusted(&trust_store, project_trust_id(PROJECT));
    for channel in [
        SourceChannel::Instructions,
        SourceChannel::Skills,
        SourceChannel::Hooks,
        SourceChannel::Helpers,
        SourceChannel::McpLocal,
    ] {
        let error = authority
            .admit_source(
                project_trust_id(PROJECT),
                SourceAdmissionRequest {
                    channel,
                    path: None,
                    observed_token: None,
                    permission_mode: PermissionMode::FullAccess,
                },
            )
            .expect_err("hostile project files do not activate unavailable channels");
        assert_eq!(
            error,
            TrustAdmissionError::DeniedByPolicy {
                reason: SourceDenyReason::ChannelUnavailable
            }
        );
    }
}
