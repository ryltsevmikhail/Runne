//! Narrow opt-in transport for the signed Linux enrollment qualification hook.

use std::path::{Path, PathBuf};

pub const FIXTURE_ROOT_ENV: &str = "RUNNE_D1_1B_POST_DELETE_KILL_FIXTURE_ROOT";
const DIAGNOSTIC_FILE: &str = "linux-enrollment-stage.log";
const DIAGNOSTIC_STAGES: &str = "begin_snapshot|writer_launch|writer_claim_and_relay|writer_installed_spec|writer_endpoint_handoff|writer_release_tuple|writer_private_endpoint|writer_endpoint_offer_prepare|writer_child_spawn|writer_endpoint_send|writer_spawn_startup_handshake|writer_capability_before_spawn|writer_broker_handoff|writer_spawn_and_handshake|writer_post_spawn_revalidation|writer_channel_binding|writer_process_claim_facts|writer_claim_measurements|writer_claim_preflight|writer_peer_remeasurement|writer_peer_release_match|writer_live_session|writer_ticket_claim_pipeline|claim_issue_context|claim_ticket_authority|claim_issue_ticket|claim_ticket_accept|recovery_mark_native_effect|recovery_readback|recovery_bind_readback|recovery_lifecycle_snapshot|recovery_completion_preflight|recovery_complete|recovery_readback_access_denied|recovery_readback_unsupported|recovery_readback_corrupt|recovery_readback_conflict|recovery_readback_unavailable|recovery_readback_operation_failed|recovery_readback_invalid|recovery_readback_not_found|recovery_readback_enrollment_incomplete|recovery_readback_migration_incomplete|recovery_readback_source_revision|recovery_readback_other_secure_store|writer_relay_encode|writer_relay_frame_write|writer_relay_peer_revalidation|writer_secret_relay_offer|writer_desktop_ack_read|writer_desktop_ack_accept|writer_terminal_readback_prepare|writer_terminal_readback|writer_terminal_live_session|writer_terminal_peer_revalidation|writer_terminal_snapshot_encode|writer_channel_terminate|writer_terminal_frame_write|provider_compose_ready|provider_compose_none|provider_compose_profile_binding|provider_compose_provider_stores|provider_compose_recovery|provider_compose_authority|provider_compose_credential_reader|provider_compose_credential_recovery|provider_compose_journal_key|provider_compose_effect_proof|provider_compose_other|provider_trust_gate|provider_projection_ready|provider_projection_unavailable|provider_projection_conflict|provider_projection_other|provider_admission_repository|provider_admission_policy|provider_admission_authority|provider_admission_budget|provider_admission_prepare|provider_admission_conflict|provider_admission_uncertain|provider_admission_other|provider_dispatch_streaming|provider_dispatch_existing|provider_dispatch_rejected|provider_dispatch_uncertain";
const DEEPSEEK_DIAGNOSTIC_STAGES: &str = "deepseek_receipt_rejected|deepseek_request_id_rejected|deepseek_materialization_started|deepseek_materialized|deepseek_materialization_missing|deepseek_materialization_denied|deepseek_authorization_header_rejected|deepseek_request_send_started|deepseek_request_send_failed|deepseek_http_status_200|deepseek_http_status_400|deepseek_http_status_401|deepseek_http_status_402|deepseek_http_status_403|deepseek_http_status_404|deepseek_http_status_429|deepseek_http_status_2xx|deepseek_http_status_3xx|deepseek_http_status_4xx|deepseek_http_status_5xx|deepseek_http_status_other|deepseek_contract_sse|deepseek_contract_json_rejection|deepseek_contract_rejected|deepseek_body_idle_timeout|deepseek_body_read_failed|deepseek_body_chunk_limit|deepseek_body_byte_limit|deepseek_body_empty|deepseek_body_complete|deepseek_response_construction_failed|deepseek_decode_ok|deepseek_decode_malformed|deepseek_decode_unknown_event|deepseek_decode_correlation|deepseek_decode_transition|deepseek_decode_limit|deepseek_decode_terminal_missing|deepseek_decode_usage_invalid|deepseek_stream_store_failed|deepseek_stream_stored|deepseek_deadline_expired";

include!("linux_native_enrollment_qualification_decode.rs");

/// Records one fixed native Linux enrollment stage when qualification logging is opted in.
///
/// Unknown stage names are ignored so this interface cannot become a payload log.
pub fn record_enrollment_stage(stage: &'static str) {
    const ALLOWED: &[&str] = &[
        "resource_hint_missing",
        "writer_capability_begin",
        "writer_capability_ready",
        "writer_capability_failed",
        "measurement_begin",
        "measurement_ready",
        "measurement_failed",
        "transition_begin",
        "transition_ready",
        "transition_failed",
        "profile_install_ready",
        "profile_install_failed",
        "capability_profile_runtime",
        "capability_peer_paths",
        "capability_policy",
        "capability_trust",
        "capability_admission",
        "capability_identity",
        "capability_refresh",
        "capability_peer_recheck",
        "capability_revalidate_policy",
        "capability_revalidate_trust",
        "capability_revalidate_time",
        "capability_revalidate_admission",
        "capability_artifact",
        "capability_measurement",
        "capability_measurement_facts",
    ];
    if !ALLOWED.contains(&stage) {
        return;
    }
    let Ok(Some(root)) = fixture_root_from_env() else {
        return;
    };
    append_diagnostic(&root, stage, None);
}

pub fn record_enrollment_stage_outcome(stage: &'static str, succeeded: bool) {
    if !diagnostic_stage_allowed(stage) {
        return;
    }
    let Ok(Some(root)) = fixture_root_from_env() else {
        return;
    };
    append_diagnostic(&root, stage, Some(succeeded));
}

fn diagnostic_stage_allowed(stage: &'static str) -> bool {
    [DIAGNOSTIC_STAGES, DEEPSEEK_DIAGNOSTIC_STAGES]
        .into_iter()
        .any(|stages| stages.split('|').any(|allowed| allowed == stage))
}

fn append_diagnostic(root: &Path, stage: &str, outcome: Option<bool>) {
    let line = match outcome {
        Some(true) => format!("stage={stage} outcome=ok"),
        Some(false) => format!("stage={stage} outcome=failed"),
        None => format!("stage={stage}"),
    };
    append_diagnostic_line(root, &line);
}

fn append_diagnostic_line(root: &Path, line: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let path = root.join(DIAGNOSTIC_FILE);
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
    else {
        return;
    };
    let Ok(metadata) = file.metadata() else {
        return;
    };
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() >= 65_536
    {
        return;
    }
    let mut record = line.as_bytes().to_vec();
    record.push(b'\n');
    if file.write(&record).ok() != Some(record.len()) {
        return;
    }
    let _ = file.sync_data();
}

#[derive(Debug)]
pub struct QualificationFixtureError;

/// Reads and validates the private owner-controlled fixture root, if opted in.
///
/// # Errors
///
/// Returns an error when the supplied root is not canonical, private, and owner-controlled.
pub fn fixture_root_from_env() -> Result<Option<PathBuf>, QualificationFixtureError> {
    let Some(root) = std::env::var_os(FIXTURE_ROOT_ENV) else {
        return Ok(None);
    };
    validate_fixture_root(Path::new(&root)).map(Some)
}

/// Validates the same exact owner/private-directory constraint at each process boundary.
///
/// # Errors
///
/// Returns an error unless both the canonical root and its parent are private owner directories.
pub fn validate_fixture_root(root: &Path) -> Result<PathBuf, QualificationFixtureError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !root.is_absolute() {
        return Err(QualificationFixtureError);
    }
    let canonical = std::fs::canonicalize(root).map_err(|_| QualificationFixtureError)?;
    if canonical != root {
        return Err(QualificationFixtureError);
    }
    let root_metadata = std::fs::symlink_metadata(root).map_err(|_| QualificationFixtureError)?;
    let parent = root.parent().ok_or(QualificationFixtureError)?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_| QualificationFixtureError)?;
    let owner = rustix::process::geteuid().as_raw();
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || root_metadata.uid() != owner
        || parent_metadata.uid() != owner
        || root_metadata.permissions().mode() & 0o077 != 0
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(QualificationFixtureError);
    }
    Ok(canonical)
}

/// Forwards only the validated fixture path across the desktop's `env_clear` boundary.
///
/// # Errors
///
/// Returns an error when an opted-in root fails path or permission validation.
pub fn forward_fixture_root(
    command: &mut std::process::Command,
) -> Result<(), QualificationFixtureError> {
    if let Some(root) = fixture_root_from_env()? {
        command.env(FIXTURE_ROOT_ENV, root);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

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
}
