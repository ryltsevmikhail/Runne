use runne_application::ports::TaskRunAssignmentIdentity;
use runne_domain::id::IntegrityDigest;
use runne_store::store::taskrun_tool_invocation::{ToolInvocationBindingV1, TrustedToolReceiptV1};
use sha2::{Digest, Sha256};

pub(super) struct Observation<'a> {
    pub reason: u8,
    pub child_spawned: bool,
    pub go_released: bool,
    pub cleanup_proved: bool,
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout_observed_bytes: u64,
    pub stderr_observed_bytes: u64,
    pub observed_bytes_overflowed: bool,
    pub stdout_eof: bool,
    pub stderr_eof: bool,
    pub exit_code: Option<i32>,
    pub helper_error_effect_started: Option<bool>,
}

pub(super) fn persist(
    store: &runne_store::store::StoreTransaction,
    provider: &crate::canonical_provider::DaemonCanonicalProviderService,
    binding: &ToolInvocationBindingV1,
    assignment: &TaskRunAssignmentIdentity,
    observation: Observation<'_>,
) -> Result<(), ()> {
    const STDOUT_AUDIT_CAP: usize = 11_500;
    const STDERR_AUDIT_CAP: usize = 3_500;
    let stdout = &observation.stdout[..observation.stdout.len().min(STDOUT_AUDIT_CAP)];
    let stderr = &observation.stderr[..observation.stderr.len().min(STDERR_AUDIT_CAP)];
    let mut payload = Vec::with_capacity(96 + stdout.len() + stderr.len());
    payload.extend_from_slice(b"RUNNE_D2_AUDIT_V1\0");
    payload.push(observation.reason);
    let mut flags = 0_u16;
    flags |= u16::from(observation.child_spawned);
    flags |= u16::from(observation.go_released) << 1;
    flags |= u16::from(observation.cleanup_proved) << 2;
    flags |=
        u16::from(observation.stdout_truncated || observation.stdout.len() > stdout.len()) << 3;
    flags |=
        u16::from(observation.stderr_truncated || observation.stderr.len() > stderr.len()) << 4;
    flags |= u16::from(observation.observed_bytes_overflowed) << 5;
    flags |= u16::from(observation.stdout_eof) << 6;
    flags |= u16::from(observation.stderr_eof) << 7;
    flags |= u16::from(observation.helper_error_effect_started.unwrap_or(false)) << 8;
    flags |= u16::from(observation.helper_error_effect_started.is_some()) << 9;
    payload.extend_from_slice(&flags.to_be_bytes());
    payload.extend_from_slice(&observation.exit_code.unwrap_or(i32::MIN).to_be_bytes());
    payload.extend_from_slice(&observation.stdout_observed_bytes.to_be_bytes());
    payload.extend_from_slice(&observation.stderr_observed_bytes.to_be_bytes());
    payload.extend_from_slice(&(stdout.len() as u16).to_be_bytes());
    payload.extend_from_slice(&(stderr.len() as u16).to_be_bytes());
    payload.extend_from_slice(stdout);
    payload.extend_from_slice(stderr);
    if payload.len() > 16 * 1024 {
        return Err(());
    }
    let actual_length = observation
        .stdout_observed_bytes
        .saturating_add(observation.stderr_observed_bytes);
    let truncated = observation.stdout_truncated
        || observation.stderr_truncated
        || observation.stdout.len() > stdout.len()
        || observation.stderr.len() > stderr.len();
    let digest = IntegrityDigest::from_bytes(Sha256::digest(&payload).into());
    let encrypted = provider.seal_d2_tool_receipt(
        binding.key.taskrun_id,
        binding.key.attempt_id,
        binding.key.cycle_id,
        binding.key.proposal_index,
        binding.semantic_digest,
        &payload,
    )?;
    store
        .record_taskrun_tool_audit_payload(
            TrustedToolReceiptV1 {
                key: binding.key,
                semantic_digest: binding.semantic_digest,
                receipt_payload: encrypted,
                result_digest: digest,
                actual_length,
                truncated,
                assignment: assignment.clone(),
            },
            unix_millis(),
        )
        .map_err(|_| ())?;
    Ok(())
}

pub(super) fn helper_error_effect_started(stdout: &[u8]) -> Option<bool> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HelperError {
        status: String,
        version: u8,
        error: String,
        effect_started: bool,
    }
    let error: HelperError = serde_json::from_slice(stdout).ok()?;
    const CODES: &[&str] = &[
        "input_bound",
        "invalid_request",
        "root_changed",
        "target_changed",
        "content_bound",
        "invalid_content",
        "target_exists_or_denied",
        "absence_precondition_required",
        "sync_failed",
        "target_invalid",
        "operation_uncertain",
        "read_denied",
        "root_invalid",
        "stat_failed",
        "read_failed",
        "write_failed",
        "path_denied",
        "command_spawn_denied",
        "command_spawn_access",
        "command_spawn_missing",
        "command_spawn_policy",
        "command_spawn_other",
    ];
    (error.status == "error" && error.version == 1 && CODES.contains(&error.error.as_str()))
        .then_some(error.effect_started)
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::helper_error_effect_started;

    #[test]
    fn helper_error_effect_started_is_retained_for_invalid_receipt() {
        let started =
            br#"{"status":"error","version":1,"error":"invalid_content","effect_started":true}"#;
        let not_started =
            br#"{"status":"error","version":1,"error":"invalid_content","effect_started":false}"#;
        assert_eq!(helper_error_effect_started(started), Some(true));
        assert_eq!(helper_error_effect_started(not_started), Some(false));
    }
}

pub(super) fn record_command_failure_stage(stdout: &[u8]) {
    if stdout.len() > 512 {
        return;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(stdout) else {
        return;
    };
    if value["status"] != "error" || value["version"] != 1 {
        return;
    }
    let stage = match value["error"].as_str() {
        Some("command_spawn_access") => "effect_command_access",
        Some("command_spawn_missing") => "effect_command_missing",
        Some("command_spawn_policy") => "effect_command_policy",
        Some("command_spawn_other") => "effect_command_other",
        _ => return,
    };
    crate::application::exec_taskrun_worker::provider::d2_stage(stage);
}
