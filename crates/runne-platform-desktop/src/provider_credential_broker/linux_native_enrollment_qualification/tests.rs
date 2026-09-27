use super::*;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn every_scanner_failure_diagnostic_is_allowlisted() {
    const EXPECTED: &[&str] = &[
        "provider_redaction_start_recovery_load",
        "provider_redaction_start_purge",
        "provider_redaction_start_matcher_validation",
        "provider_redaction_restart_recovery_load",
        "provider_redaction_restart_authority_binding",
        "provider_redaction_restart_checkpoint_validation",
        "provider_redaction_restart_tail_load",
        "provider_redaction_restart_tail_purge",
        "provider_redaction_restart_matcher_validation",
        "provider_redaction_ingest_cursor_validation",
        "provider_redaction_ingest_tail_load",
        "provider_redaction_ingest_tail_put",
        "provider_redaction_ingest_checkpoint_construction",
        "provider_redaction_ingest_checkpoint_persist",
        "provider_redaction_ingest_checkpoint_advance",
        "provider_redaction_ingest_previous_tail_delete",
        "provider_redaction_ingest_scanner_classification",
        "provider_redaction_complete_tail_load",
        "provider_redaction_complete_tail_put",
        "provider_redaction_complete_checkpoint_construction",
        "provider_redaction_complete_checkpoint_persist",
        "provider_redaction_complete_checkpoint_advance",
        "provider_redaction_complete_tail_purge",
        "provider_redaction_complete_scanner_classification",
        "provider_redaction_error_native_unavailable",
        "provider_redaction_error_native_not_found",
        "provider_redaction_error_native_corrupt",
        "provider_redaction_error_native_binding_mismatch",
        "provider_redaction_error_recovery_unavailable",
        "provider_redaction_error_recovery_conflict",
        "provider_redaction_error_recovery_corrupt",
        "provider_redaction_error_recovery_missing",
        "provider_redaction_error_binding_mismatch",
        "provider_redaction_error_checkpoint_mismatch",
        "provider_redaction_error_invalid_binding",
        "provider_redaction_error_invalid_checkpoint",
        "provider_redaction_error_matcher_unavailable",
        "provider_redaction_error_scanner_unavailable",
        "provider_redaction_error_output_limit_exceeded",
    ];
    for stage in EXPECTED {
        assert!(
            diagnostic_stage_allowed(stage),
            "missing fixed scanner diagnostic: {stage}"
        );
    }
    assert!(!diagnostic_stage_allowed(
        "provider_redaction_untrusted_input"
    ));
}

#[test]
fn accepts_private_canonical_root_and_rejects_loose_or_linked_roots() {
    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("fixture");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(validate_fixture_root(&root).unwrap(), root);

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(validate_fixture_root(&root).is_err());
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = parent.path().join("link");
    std::os::unix::fs::symlink(&root, &link).unwrap();
    assert!(validate_fixture_root(&link).is_err());
}

#[test]
fn rejects_public_parent_directory() {
    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let root = parent.path().join("fixture");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(validate_fixture_root(&root).is_err());
}

#[test]
fn diagnostic_append_rejects_symlink_fifo_and_special_mode_files() {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("fixture");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let target = root.join("target");
    std::fs::write(&target, b"").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, root.join(DIAGNOSTIC_FILE)).unwrap();
    append_diagnostic(&root, "measurement_ready", None);
    assert_eq!(std::fs::read(&target).unwrap(), b"");
    std::fs::remove_file(root.join(DIAGNOSTIC_FILE)).unwrap();

    let root_fd = rustix::fs::open(
        "/",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    rustix::fs::mkfifoat(
        &root_fd,
        root.join(DIAGNOSTIC_FILE),
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    append_diagnostic(&root, "measurement_ready", None);
    assert!(
        std::fs::symlink_metadata(root.join(DIAGNOSTIC_FILE))
            .unwrap()
            .file_type()
            .is_fifo()
    );
    std::fs::remove_file(root.join(DIAGNOSTIC_FILE)).unwrap();

    std::fs::write(root.join(DIAGNOSTIC_FILE), b"").unwrap();
    std::fs::set_permissions(
        root.join(DIAGNOSTIC_FILE),
        std::fs::Permissions::from_mode(0o2600),
    )
    .unwrap();
    append_diagnostic(&root, "measurement_ready", None);
    assert_eq!(std::fs::read(root.join(DIAGNOSTIC_FILE)).unwrap(), b"");
}

#[test]
fn child_process_stage_record_is_visible_in_fixture_log() {
    const CHILD: &str = "provider_credential_broker::linux_native_enrollment_qualification::tests::write_stage_child";
    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("fixture");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD])
        .env(FIXTURE_ROOT_ENV, &root)
        .env("RUNNE_QUALIFICATION_LOG_CHILD", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        std::fs::metadata(root.join(DIAGNOSTIC_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert_eq!(
        std::fs::read_to_string(root.join(DIAGNOSTIC_FILE)).unwrap(),
        "stage=claim_issue_ticket outcome=failed\nstage=provider_projection_ready outcome=ok\ndeepseek_decode_detail_v1 phase=2 event=4 node=8 field=17 issue=9\n"
    );
}

#[test]
fn write_stage_child() {
    if std::env::var_os("RUNNE_QUALIFICATION_LOG_CHILD").is_some() {
        record_enrollment_stage_outcome("claim_issue_ticket", false);
        record_enrollment_stage_outcome("provider_projection_ready", true);
        record_deepseek_decode_detail((2, 4, 8, 17, 9));
        record_deepseek_decode_detail((255, 255, 255, 255, 255));
        record_enrollment_stage_outcome("untrusted_payload", false);
    }
}
