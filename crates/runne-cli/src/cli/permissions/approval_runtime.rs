#[derive(Clone, Debug, Eq, PartialEq)]
struct ApprovalResponseIntent {
    approval_id: CanonicalId,
    command_id: CanonicalId,
    idempotency_key: String,
    decision: runne_runtime_client::ApprovalDecisionDto,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApprovalSnapshot {
    approval_id: CanonicalId,
    task_run_id: CanonicalId,
    attempt_id: Option<CanonicalId>,
    invocation_id: CanonicalId,
    action: String,
    resource: String,
    action_digest: [u8; 32],
    policy_revision: u64,
    request_version: u64,
    approval_generation: u64,
    expires_at: i64,
    risk_summary: String,
    state: runne_runtime_client::ApprovalStateDto,
}

impl From<runne_runtime_client::ApprovalSummaryDto> for ApprovalSnapshot {
    fn from(value: runne_runtime_client::ApprovalSummaryDto) -> Self {
        Self {
            approval_id: value.approval_id(),
            task_run_id: value.task_run_id(),
            attempt_id: value.attempt_id(),
            invocation_id: value.invocation_id(),
            action: value.action().to_owned(),
            resource: value.resource().to_owned(),
            action_digest: *value.action_digest(),
            policy_revision: value.policy_revision(),
            request_version: value.request_version(),
            approval_generation: value.approval_generation(),
            expires_at: value.expires_at(),
            risk_summary: value.risk_summary().to_owned(),
            state: value.state(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ApprovalAck {
    approval_id: CanonicalId,
    task_run_id: CanonicalId,
    new_version: u64,
    state: runne_runtime_client::ApprovalStateDto,
}

impl From<runne_runtime_client::ApprovalDecisionAcknowledgementDto> for ApprovalAck {
    fn from(value: runne_runtime_client::ApprovalDecisionAcknowledgementDto) -> Self {
        Self {
            approval_id: value.approval_id(),
            task_run_id: value.task_run_id(),
            new_version: value.new_version(),
            state: value.state(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApprovalReconciliation {
    DurablyRecorded(ApprovalAck),
    NotCommittedRetryable,
    Indeterminate,
    Unexpected,
}

#[derive(Debug)]
enum ApprovalRuntimeError {
    NotFound,
    UnknownAfterSend,
    InvalidWitness,
    Api(RuntimeApiError),
}

type ApprovalRuntimeFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ApprovalRuntimeError>> + 'a>>;

trait ApprovalResponseRuntime: PermissionsRuntime {
    fn approval_session_info(&self) -> runne_runtime_client::RuntimeSessionInfo;
    fn read_approval(
        &self,
        approval_id: CanonicalId,
    ) -> ApprovalRuntimeFuture<'_, ApprovalSnapshot>;
    fn decide_approval(
        &self,
        record: &ApprovalDecisionRecoveryRecordV1,
    ) -> ApprovalRuntimeFuture<'_, ApprovalAck>;
    fn reconcile_approval(
        &self,
        record: &ApprovalDecisionRecoveryRecordV1,
    ) -> ApprovalRuntimeFuture<'_, ApprovalReconciliation>;
}

impl ApprovalResponseRuntime for AuthenticatedRuntimeClient {
    fn approval_session_info(&self) -> runne_runtime_client::RuntimeSessionInfo {
        self.session_info().clone()
    }

    fn read_approval(
        &self,
        approval_id: CanonicalId,
    ) -> ApprovalRuntimeFuture<'_, ApprovalSnapshot> {
        Box::pin(async move {
            Self::get_approval(self, approval_id)
                .await
                .map(ApprovalSnapshot::from)
                .map_err(|error| {
                    if error.kind() == RuntimeApiErrorKind::NotFound {
                        ApprovalRuntimeError::NotFound
                    } else {
                        ApprovalRuntimeError::Api(error)
                    }
                })
        })
    }

    fn decide_approval(
        &self,
        record: &ApprovalDecisionRecoveryRecordV1,
    ) -> ApprovalRuntimeFuture<'_, ApprovalAck> {
        let request = approval_decision_request(record);
        Box::pin(async move {
            let request = request?;
            Self::decide_approval(self, request)
                .await
                .map(ApprovalAck::from)
                .map_err(approval_send_error)
        })
    }

    fn reconcile_approval(
        &self,
        record: &ApprovalDecisionRecoveryRecordV1,
    ) -> ApprovalRuntimeFuture<'_, ApprovalReconciliation> {
        let request = approval_reconciliation_request(record);
        Box::pin(async move {
            let request = request.map_err(|_| ApprovalRuntimeError::InvalidWitness)?;
            Self::reconcile_command(self, request)
                .await
                .map(|result| match result {
                    runne_runtime_client::CommandReconciliationDisposition::NotCommittedRetryable => {
                        ApprovalReconciliation::NotCommittedRetryable
                    }
                    runne_runtime_client::CommandReconciliationDisposition::Indeterminate => {
                        ApprovalReconciliation::Indeterminate
                    }
                    runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
                        runne_runtime_client::CommandReconciliationOutcome::ApprovalDecision(ack),
                    ) => ApprovalReconciliation::DurablyRecorded(ack.into()),
                    runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(_) => {
                        ApprovalReconciliation::Unexpected
                    }
                })
                .map_err(ApprovalRuntimeError::Api)
        })
    }
}

trait ApprovalConsent {
    type Token;

    fn present(
        &self,
        intent: &ApprovalResponseIntent,
        approval: &ApprovalSnapshot,
        digest: [u8; 32],
    ) -> Result<Self::Token, ApprovalConfirmationError>;

    fn consume(&self, token: Self::Token, digest: [u8; 32], expires_at: i64) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApprovalConfirmationError {
    Unavailable,
    Declined,
    Expired,
}

struct NativeApprovalConsent;

#[cfg(target_os = "linux")]
impl ApprovalConsent for NativeApprovalConsent {
    type Token = runne_platform_desktop::LinuxApprovalConfirmation;

    fn present(
        &self,
        intent: &ApprovalResponseIntent,
        approval: &ApprovalSnapshot,
        digest: [u8; 32],
    ) -> Result<Self::Token, ApprovalConfirmationError> {
        let review = runne_platform_desktop::LinuxApprovalReview {
            approval_id: approval.approval_id,
            task_run_id: approval.task_run_id,
            attempt_id: approval.attempt_id,
            invocation_id: approval.invocation_id,
            command_id: intent.command_id,
            action: approval.action.clone(),
            resource: approval.resource.clone(),
            risk_summary: approval.risk_summary.clone(),
            action_digest: approval.action_digest,
            policy_revision: approval.policy_revision,
            request_version: approval.request_version,
            approval_generation: approval.approval_generation,
            decision: intent.decision,
            digest,
            expires_at_unix_ms: approval.expires_at,
        };
        runne_platform_desktop::confirm_linux_approval(&review).map_err(|error| match error {
            runne_platform_desktop::ApprovalConfirmationError::Declined => {
                ApprovalConfirmationError::Declined
            }
            runne_platform_desktop::ApprovalConfirmationError::Expired => {
                ApprovalConfirmationError::Expired
            }
            runne_platform_desktop::ApprovalConfirmationError::InvalidReview
            | runne_platform_desktop::ApprovalConfirmationError::Unavailable => {
                ApprovalConfirmationError::Unavailable
            }
        })
    }

    fn consume(&self, token: Self::Token, digest: [u8; 32], expires_at: i64) -> bool {
        token.consume(digest, expires_at)
    }
}

#[cfg(not(target_os = "linux"))]
impl ApprovalConsent for NativeApprovalConsent {
    type Token = ();

    fn present(
        &self,
        _intent: &ApprovalResponseIntent,
        _approval: &ApprovalSnapshot,
        _digest: [u8; 32],
    ) -> Result<Self::Token, ApprovalConfirmationError> {
        Err(ApprovalConfirmationError::Unavailable)
    }

    fn consume(&self, _token: Self::Token, _digest: [u8; 32], _expires_at: i64) -> bool {
        false
    }
}

fn approval_reconciliation_request(
    record: &ApprovalDecisionRecoveryRecordV1,
) -> Result<runne_runtime_client::CommandReconciliationRequest, RecoveryError> {
    let identity = runne_runtime_client::CommandIdentity::new(
        record.command_id,
        record.idempotency_key.clone(),
    )
    .map_err(|_| RecoveryError::Corrupt)?;
    let bytes = hex::decode(&record.action_digest).map_err(|_| RecoveryError::Corrupt)?;
    let action_digest: [u8; 32] = bytes.try_into().map_err(|_| RecoveryError::Corrupt)?;
    runne_runtime_client::CommandReconciliationRequest::approval_decision(
        identity,
        record.approval_id,
        record.expected_version,
        record.decision.into(),
        action_digest,
        record.policy_revision,
        record.approval_generation,
    )
    .map_err(|_| RecoveryError::Corrupt)
}

fn decode_mode_recovery_record(
    bytes: &[u8],
    command_id: CanonicalId,
) -> Result<PermissionRecoveryRecordV1, CliError> {
    match decode_any_command_record(bytes).map_err(|error| recovery_cli_error(command_id, error))? {
        RecoveredCommandRecord::PermissionMode(record) => Ok(record),
        RecoveredCommandRecord::ApprovalDecision(_) => {
            Err(CliError::PermissionRecoveryConflict(command_id))
        }
    }
}
