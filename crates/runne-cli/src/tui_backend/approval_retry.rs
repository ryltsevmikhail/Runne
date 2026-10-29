//! A fresh key gesture may advance only past an authoritative no-commit witness.
use crate::{
    ApprovalConsent, ApprovalReconciliation, ApprovalResponseIntent, ApprovalResponseRuntime,
    CliError, CommandOutput, PermissionRecoveryIndex, StableRuntimeIdentity, approval_ack_matches,
    approval_runtime_cli_error, decode_approval_recovery_record,
    execute_approval_response_with_consent, match_approval_recovery_record, recovery_cli_error,
    render_approval_ack, scope_digest,
};
use runne_runtime_client::CanonicalId;
use sha2::{Digest, Sha256};

pub(super) async fn execute<
    R: ApprovalResponseRuntime,
    I: PermissionRecoveryIndex,
    C: ApprovalConsent,
>(
    runtime: &R,
    mut intent: ApprovalResponseIntent,
    index: &I,
    consent: &C,
) -> Result<CommandOutput, CliError> {
    let stable = StableRuntimeIdentity::from_session(&runtime.approval_session_info())
        .map_err(|_| CliError::PermissionCommandUnavailable(intent.command_id))?;
    let scope = scope_digest(&stable);
    for _ in 0..32 {
        let Some(bytes) = index
            .read_existing(&scope, intent.command_id)
            .map_err(|error| recovery_cli_error(intent.command_id, error))?
        else {
            return execute_approval_response_with_consent(runtime, intent, index, consent).await;
        };
        let record = decode_approval_recovery_record(&bytes)
            .map_err(|error| recovery_cli_error(intent.command_id, error))?;
        let previous = ApprovalResponseIntent {
            decision: record.decision.into(),
            ..intent.clone()
        };
        match_approval_recovery_record(&record, &previous, &stable)?;
        match runtime
            .reconcile_approval(&record)
            .await
            .map_err(|error| approval_runtime_cli_error(intent.command_id, error))?
        {
            ApprovalReconciliation::NotCommittedRetryable => {
                intent.command_id = successor(intent.command_id)?;
                intent.idempotency_key = format!("tui-approval-retry:{}", intent.command_id);
            }
            ApprovalReconciliation::DurablyRecorded(ack) if approval_ack_matches(&ack, &record) => {
                return Ok(render_approval_ack(ack, &record));
            }
            _ => return Err(CliError::PermissionCommandUnknown(intent.command_id)),
        }
    }
    Err(CliError::PermissionCommandUnavailable(intent.command_id))
}

fn successor(previous: CanonicalId) -> Result<CanonicalId, CliError> {
    // Keep the original UUIDv7 timestamp; derive a stable domain-separated random tail.
    // Concurrent/reopened clients therefore converge on one next immutable witness.
    let original: [u8; 16] = hex::decode(previous.to_string().replace('-', ""))
        .map_err(|_| CliError::PermissionRecoveryCorrupt(previous))?
        .try_into()
        .map_err(|_| CliError::PermissionRecoveryCorrupt(previous))?;
    let mut hash = Sha256::new();
    hash.update(b"runne:tui-approval-retry:v1\0");
    hash.update(original);
    let digest = hash.finalize();
    let mut bytes = original;
    bytes[6..].copy_from_slice(&digest[..10]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let encoded = hex::encode(bytes);
    let value = format!(
        "{}-{}-{}-{}-{}",
        &encoded[..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..]
    );
    CanonicalId::parse(&value).map_err(|_| CliError::PermissionRecoveryCorrupt(previous))
}
