const APPROVAL_RECOVERY_RECORD_VERSION: u16 = 1;
const APPROVAL_RECOVERY_CONTRACT_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum StoredApprovalDecision {
    Approve,
    Deny,
}

impl From<runne_runtime_client::ApprovalDecisionDto> for StoredApprovalDecision {
    fn from(value: runne_runtime_client::ApprovalDecisionDto) -> Self {
        match value {
            runne_runtime_client::ApprovalDecisionDto::Approve => Self::Approve,
            runne_runtime_client::ApprovalDecisionDto::Deny => Self::Deny,
        }
    }
}

impl From<StoredApprovalDecision> for runne_runtime_client::ApprovalDecisionDto {
    fn from(value: StoredApprovalDecision) -> Self {
        match value {
            StoredApprovalDecision::Approve => Self::Approve,
            StoredApprovalDecision::Deny => Self::Deny,
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalDecisionRecoveryRecordV1 {
    record_version: u16,
    contract_version: u16,
    command_id: CanonicalId,
    idempotency_key: String,
    approval_id: CanonicalId,
    task_run_id: CanonicalId,
    attempt_id: Option<CanonicalId>,
    invocation_id: CanonicalId,
    expected_version: u64,
    decision: StoredApprovalDecision,
    action_digest: String,
    policy_revision: u64,
    approval_generation: u64,
    expires_at_unix_ms: i64,
    scope_digest: String,
    intent_digest: String,
    review_digest: String,
    stable_runtime: StableRuntimeIdentity,
    audit: RuntimeAuditSnapshot,
}

enum RecoveredCommandRecord {
    PermissionMode(PermissionRecoveryRecordV1),
    ApprovalDecision(ApprovalDecisionRecoveryRecordV1),
}

fn decode_any_command_record(bytes: &[u8]) -> Result<RecoveredCommandRecord, RecoveryError> {
    if let Ok(record) = decode_recovery_record(bytes) {
        return Ok(RecoveredCommandRecord::PermissionMode(record));
    }
    decode_approval_recovery_record(bytes).map(RecoveredCommandRecord::ApprovalDecision)
}

fn make_approval_recovery_record(
    intent: &ApprovalResponseIntent,
    approval: &ApprovalSnapshot,
    stable: StableRuntimeIdentity,
    audit: RuntimeAuditSnapshot,
) -> Result<Vec<u8>, RecoveryError> {
    stable.validate()?;
    audit.validate()?;
    let record = ApprovalDecisionRecoveryRecordV1 {
        record_version: APPROVAL_RECOVERY_RECORD_VERSION,
        contract_version: APPROVAL_RECOVERY_CONTRACT_VERSION,
        command_id: intent.command_id,
        idempotency_key: intent.idempotency_key.clone(),
        approval_id: approval.approval_id,
        task_run_id: approval.task_run_id,
        attempt_id: approval.attempt_id,
        invocation_id: approval.invocation_id,
        expected_version: approval.request_version,
        decision: intent.decision.into(),
        action_digest: hex::encode(approval.action_digest),
        policy_revision: approval.policy_revision,
        approval_generation: approval.approval_generation,
        expires_at_unix_ms: approval.expires_at,
        scope_digest: scope_digest(&stable),
        intent_digest: approval_intent_digest(intent, approval, &stable),
        review_digest: hex::encode(approval_review_digest(intent, approval, &stable)),
        stable_runtime: stable,
        audit,
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| RecoveryError::Io)?;
    (bytes.len() <= MAX_RECOVERY_RECORD_BYTES)
        .then_some(bytes)
        .ok_or(RecoveryError::Io)
}

fn decode_approval_recovery_record(
    bytes: &[u8],
) -> Result<ApprovalDecisionRecoveryRecordV1, RecoveryError> {
    if bytes.is_empty() || bytes.len() > MAX_RECOVERY_RECORD_BYTES {
        return Err(RecoveryError::Corrupt);
    }
    let record: ApprovalDecisionRecoveryRecordV1 =
        serde_json::from_slice(bytes).map_err(|_| RecoveryError::Corrupt)?;
    record
        .stable_runtime
        .validate()
        .map_err(|_| RecoveryError::Corrupt)?;
    record
        .audit
        .validate()
        .map_err(|_| RecoveryError::Corrupt)?;
    runne_runtime_client::CommandIdentity::new(record.command_id, record.idempotency_key.clone())
        .map_err(|_| RecoveryError::Corrupt)?;
    if record.record_version != APPROVAL_RECOVERY_RECORD_VERSION
        || record.contract_version != APPROVAL_RECOVERY_CONTRACT_VERSION
        || record.expected_version == 0
        || record.expected_version.checked_add(1).is_none()
        || record.policy_revision == 0
        || record.approval_generation == 0
        || record.expires_at_unix_ms <= 0
        || record.scope_digest != scope_digest(&record.stable_runtime)
        || canonical_digest(&record.action_digest).is_err()
        || record.action_digest == "00".repeat(32)
        || canonical_digest(&record.intent_digest).is_err()
        || record.intent_digest != approval_record_intent_digest(&record)
        || canonical_digest(&record.review_digest).is_err()
    {
        return Err(RecoveryError::Corrupt);
    }
    if let Some(attempt_id) = record.attempt_id {
        canonical_uuid(&attempt_id.to_string()).map_err(|_| RecoveryError::Corrupt)?;
    }
    Ok(record)
}

fn approval_intent_digest(
    intent: &ApprovalResponseIntent,
    approval: &ApprovalSnapshot,
    stable: &StableRuntimeIdentity,
) -> String {
    let mut hash = sha2::Sha256::new();
    hash.update(b"runne:d21:cli-approval-command-witness:v1\0");
    approval_digest_common(
        &mut hash,
        &intent.command_id.to_string(),
        &intent.idempotency_key,
        stable,
    );
    approval_witness_tuple(&mut hash, approval, intent.decision);
    hex::encode(hash.finalize())
}

fn approval_record_intent_digest(record: &ApprovalDecisionRecoveryRecordV1) -> String {
    let mut hash = sha2::Sha256::new();
    hash.update(b"runne:d21:cli-approval-command-witness:v1\0");
    approval_digest_common(
        &mut hash,
        &record.command_id.to_string(),
        &record.idempotency_key,
        &record.stable_runtime,
    );
    approval_record_witness_tuple(&mut hash, record);
    hex::encode(hash.finalize())
}

fn approval_digest_common(
    hash: &mut sha2::Sha256,
    command_id: &str,
    key: &str,
    stable: &StableRuntimeIdentity,
) {
    put_digest_bytes(hash, scope_digest(stable).as_bytes());
    put_digest_bytes(hash, command_id.as_bytes());
    put_digest_bytes(hash, key.as_bytes());
}

fn approval_witness_tuple(
    hash: &mut sha2::Sha256,
    approval: &ApprovalSnapshot,
    decision: runne_runtime_client::ApprovalDecisionDto,
) {
    for value in [
        approval.approval_id.to_string(),
        approval.task_run_id.to_string(),
    ] {
        put_digest_bytes(hash, value.as_bytes());
    }
    let attempt = approval
        .attempt_id
        .map_or_else(String::new, |id| id.to_string());
    put_digest_bytes(hash, attempt.as_bytes());
    put_digest_bytes(hash, approval.invocation_id.to_string().as_bytes());
    let action_digest = hex::encode(approval.action_digest);
    put_digest_bytes(hash, action_digest.as_bytes());
    hash.update(approval.request_version.to_be_bytes());
    hash.update([approval_decision_tag(decision)]);
    hash.update(approval.policy_revision.to_be_bytes());
    hash.update(approval.approval_generation.to_be_bytes());
    hash.update(approval.expires_at.to_be_bytes());
    hash.update([approval_state_tag(approval.state)]);
}

fn approval_record_witness_tuple(
    hash: &mut sha2::Sha256,
    record: &ApprovalDecisionRecoveryRecordV1,
) {
    put_digest_bytes(hash, record.approval_id.to_string().as_bytes());
    put_digest_bytes(hash, record.task_run_id.to_string().as_bytes());
    let attempt = record
        .attempt_id
        .map_or_else(String::new, |id| id.to_string());
    put_digest_bytes(hash, attempt.as_bytes());
    put_digest_bytes(hash, record.invocation_id.to_string().as_bytes());
    put_digest_bytes(hash, record.action_digest.as_bytes());
    hash.update(record.expected_version.to_be_bytes());
    hash.update([stored_approval_decision_tag(record.decision)]);
    hash.update(record.policy_revision.to_be_bytes());
    hash.update(record.approval_generation.to_be_bytes());
    hash.update(record.expires_at_unix_ms.to_be_bytes());
    hash.update([1]);
}

const fn approval_decision_tag(decision: runne_runtime_client::ApprovalDecisionDto) -> u8 {
    match decision {
        runne_runtime_client::ApprovalDecisionDto::Approve => 1,
        runne_runtime_client::ApprovalDecisionDto::Deny => 2,
    }
}

const fn stored_approval_decision_tag(decision: StoredApprovalDecision) -> u8 {
    match decision {
        StoredApprovalDecision::Approve => 1,
        StoredApprovalDecision::Deny => 2,
    }
}

const fn approval_state_tag(state: runne_runtime_client::ApprovalStateDto) -> u8 {
    match state {
        runne_runtime_client::ApprovalStateDto::Pending => 1,
        runne_runtime_client::ApprovalStateDto::Approved => 2,
        runne_runtime_client::ApprovalStateDto::Denied => 3,
        runne_runtime_client::ApprovalStateDto::Expired => 4,
        runne_runtime_client::ApprovalStateDto::Cancelled => 5,
    }
}

fn match_approval_recovery_record(
    record: &ApprovalDecisionRecoveryRecordV1,
    intent: &ApprovalResponseIntent,
    stable: &StableRuntimeIdentity,
) -> Result<(), CliError> {
    if record.stable_runtime != *stable {
        return Err(CliError::PermissionRecoveryScopeMismatch(intent.command_id));
    }
    if record.command_id != intent.command_id
        || record.idempotency_key != intent.idempotency_key
        || record.approval_id != intent.approval_id
        || runne_runtime_client::ApprovalDecisionDto::from(record.decision) != intent.decision
        || record.scope_digest != scope_digest(stable)
        || record.intent_digest != approval_record_intent_digest(record)
    {
        return Err(CliError::PermissionRecoveryConflict(intent.command_id));
    }
    Ok(())
}
