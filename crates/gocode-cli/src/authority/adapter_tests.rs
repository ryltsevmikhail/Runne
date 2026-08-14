use std::{fs, os::unix::fs::symlink};

use super::io::create_new_with_failing_post_commit;
use super::{AuthorityFiles, CliError, SystemAuthorityFiles};

#[test]
fn rejects_symbolic_link_and_directory_artifacts() {
    let temporary = tempfile::tempdir().expect("temporary repository");
    let files = SystemAuthorityFiles::new(temporary.path().to_path_buf());
    fs::write(temporary.path().join("actual"), b"artifact").expect("artifact");
    symlink("actual", temporary.path().join("link")).expect("symbolic link");
    fs::create_dir(temporary.path().join("directory")).expect("directory");

    assert!(matches!(
        files.read_repo_public("link"),
        Err(CliError::AuthorityUnavailable)
    ));
    assert!(matches!(
        files.read_repo_public("directory"),
        Err(CliError::AuthorityUnavailable)
    ));
}

#[cfg(unix)]
#[test]
fn rejects_fifo_without_waiting_for_a_writer() {
    let temporary = tempfile::tempdir().expect("temporary repository");
    let fifo = temporary.path().join("authority.fifo");
    let status = std::process::Command::new("mkfifo")
        .arg("--mode=600")
        .arg(&fifo)
        .status()
        .expect("start mkfifo");
    assert!(status.success(), "create fifo");
    let files = SystemAuthorityFiles::new(temporary.path().to_path_buf());

    assert!(matches!(
        files.read_repo_public("authority.fifo"),
        Err(CliError::AuthorityUnavailable)
    ));
}

#[test]
fn publishes_complete_new_public_artifact_with_exact_mode_and_bytes() {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir().expect("temporary repository");
    let files = SystemAuthorityFiles::new(temporary.path().to_path_buf());
    let bytes = b"canonical authority artifact";

    files
        .create_new_repo_public("artifact.json", bytes)
        .expect("publish artifact");
    let artifact = temporary.path().join("artifact.json");
    assert_eq!(fs::read(&artifact).expect("published bytes"), bytes);
    assert_eq!(
        fs::metadata(&artifact)
            .expect("artifact metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[test]
fn publish_failure_leaves_no_final_artifact() {
    let temporary = tempfile::tempdir().expect("temporary repository");
    let files = SystemAuthorityFiles::new(temporary.path().to_path_buf());

    assert!(matches!(
        files.create_new_repo_public("missing/artifact.json", b"artifact"),
        Err(CliError::AuthorityUnavailable)
    ));
    assert!(!temporary.path().join("missing/artifact.json").exists());
}

#[test]
fn retry_accepts_only_exact_existing_bytes_and_mode() {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir().expect("temporary repository");
    let files = SystemAuthorityFiles::new(temporary.path().to_path_buf());
    let artifact = temporary.path().join("artifact.json");
    fs::write(&artifact, b"artifact").expect("artifact");
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(matches!(
        files.create_new_or_exact_repo_public("artifact.json", b"artifact"),
        Err(CliError::AuthorityArtifactExists)
    ));
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644)).expect("mode");
    files
        .create_new_or_exact_repo_public("artifact.json", b"artifact")
        .expect("exact retry");
}

#[test]
fn post_commit_probe_sync_and_cleanup_failures_still_report_committed_success() {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir().expect("temporary repository");
    let artifact = temporary.path().join("artifact.json");
    let bytes = b"committed authority artifact";
    create_new_with_failing_post_commit(&artifact, bytes, 0o644).expect("committed success");
    assert_eq!(fs::read(&artifact).expect("final bytes"), bytes);
    assert_eq!(
        fs::metadata(&artifact)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}
