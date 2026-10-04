#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteArtifactAckKind {
    PublishedOutput,
    AuditOnly,
}

fn validate_remote_artifact_ack(
    tx: &rusqlite::Transaction<'_>,
    outbox_id: [u8; 16],
    attempt_id: [u8; 16],
    settlement_digest: [u8; 32],
    receipt_digest: [u8; 32],
    expected_source_state: i64,
) -> Result<Option<RemoteArtifactAckKind>, ProviderExecutionError> {
    validate_remote_artifact_ack_inner(
        tx,
        outbox_id,
        attempt_id,
        settlement_digest,
        receipt_digest,
        expected_source_state,
        true,
    )
}

pub(crate) fn validate_remote_artifact_ack_for_readiness(
    connection: &Connection,
    outbox_id: [u8; 16],
    attempt_id: [u8; 16],
    settlement_digest: [u8; 32],
    receipt_digest: [u8; 32],
    expected_source_state: i64,
) -> Result<Option<RemoteArtifactAckKind>, ProviderExecutionError> {
    validate_remote_artifact_ack_inner(
        connection,
        outbox_id,
        attempt_id,
        settlement_digest,
        receipt_digest,
        expected_source_state,
        false,
    )
}

pub(crate) fn validate_remote_artifact_pending_application_for_readiness(
    connection: &Connection,
    outbox_id: [u8; 16],
    attempt_id: [u8; 16],
    settlement_digest: [u8; 32],
    verified: &crate::store::taskrun_submit_origin::VerifiedRemoteTerminalTaskRunSource,
) -> rusqlite::Result<bool> {
    pending_application::matches(
        connection,
        outbox_id,
        attempt_id,
        settlement_digest,
        verified,
    )
}

include!("part_05_remote_artifact_ack/validation.rs");
#[path = "part_05_remote_artifact_ack/pending_application.rs"]
mod pending_application;
