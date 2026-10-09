use serde::Deserialize;
use sha2::{Digest, Sha256};

const RECOVERY_RECORD_VERSION: u16 = 1;
const RECOVERY_CONTRACT_VERSION: u16 = 2;
const MAX_RECOVERY_RECORD_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StableRuntimeIdentity {
    profile_id: String,
    schema_hash: String,
    authority_id: String,
    principal_id: String,
    event_log_lineage_id: String,
}

impl StableRuntimeIdentity {
    fn from_session(
        info: &runne_runtime_client::RuntimeSessionInfo,
    ) -> Result<Self, RecoveryError> {
        let stable = Self {
            profile_id: info.profile_id.clone(),
            schema_hash: info.schema_hash.clone(),
            authority_id: info.authority_id.clone(),
            principal_id: info.principal_id.clone(),
            event_log_lineage_id: info.event_log_lineage_id.clone(),
        };
        stable.validate()?;
        Ok(stable)
    }

    fn validate(&self) -> Result<(), RecoveryError> {
        safe_identity_text(&self.profile_id, 128)?;
        safe_identity_text(&self.principal_id, 256)?;
        canonical_digest(&self.schema_hash)?;
        // The runtime wire identity carries this authority as lowercase hex, not UUID text.
        canonical_session_id(&self.authority_id)?;
        canonical_uuid(&self.event_log_lineage_id)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeAuditSnapshot {
    runtime_version: String,
    daemon_instance_id: String,
    launch_generation: u64,
    session_id: String,
    authorization_epoch: u64,
    certificate_sha256: String,
    capability_digest: String,
}

impl RuntimeAuditSnapshot {
    fn from_session(
        info: &runne_runtime_client::RuntimeSessionInfo,
    ) -> Result<Self, RecoveryError> {
        let audit = Self {
            runtime_version: info.runtime_version.clone(),
            daemon_instance_id: info.daemon_instance_id.clone(),
            launch_generation: info.launch_generation,
            session_id: info.session_id.clone(),
            authorization_epoch: info.authorization_epoch,
            certificate_sha256: info.certificate_sha256.clone(),
            capability_digest: info.capability_digest.clone(),
        };
        audit.validate()?;
        Ok(audit)
    }

    fn validate(&self) -> Result<(), RecoveryError> {
        safe_identity_text(&self.runtime_version, 128)?;
        canonical_uuid(&self.daemon_instance_id)?;
        canonical_session_id(&self.session_id)?;
        canonical_digest(&self.certificate_sha256)?;
        canonical_digest(&self.capability_digest)?;
        if self.launch_generation == 0 {
            return Err(RecoveryError::Corrupt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PermissionRecoveryRecordV1 {
    record_version: u16,
    contract_version: u16,
    command_id: CanonicalId,
    idempotency_key: String,
    workspace_id: CanonicalId,
    requested_mode: runne_runtime_client::PermissionModeV1,
    preset_version: u16,
    expected_authorization_revision: u64,
    expires_at_unix_ms: Option<i64>,
    scope_digest: String,
    intent_digest: String,
    stable_runtime: StableRuntimeIdentity,
    audit: RuntimeAuditSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryError {
    Io,
    Corrupt,
}

enum RecordCreateResult {
    DurableCreated,
    Existing(Vec<u8>),
}

trait PermissionRecoveryIndex {
    fn read_existing(
        &self,
        scope_digest: &str,
        command_id: CanonicalId,
    ) -> Result<Option<Vec<u8>>, RecoveryError>;

    fn create_exclusive(
        &self,
        scope_digest: &str,
        command_id: CanonicalId,
        record: &[u8],
    ) -> Result<RecordCreateResult, RecoveryError>;
}

fn scope_digest(stable: &StableRuntimeIdentity) -> String {
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:cli-permission-recovery-scope:v1\0");
    for value in [
        stable.profile_id.as_bytes(),
        stable.schema_hash.as_bytes(),
        stable.authority_id.as_bytes(),
        stable.principal_id.as_bytes(),
        stable.event_log_lineage_id.as_bytes(),
    ] {
        // Validated identity fields are bounded to at most 256 bytes.
        let length = u32::try_from(value.len())
            .expect("validated stable identity field fits the digest length prefix");
        hash.update(length.to_be_bytes());
        hash.update(value);
    }
    hex::encode(hash.finalize())
}

fn local_intent_digest(intent: &PermissionModeSetIntent, stable: &StableRuntimeIdentity) -> String {
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:cli-permission-mode-intent:v1\0");
    put_digest_bytes(&mut hash, scope_digest(stable).as_bytes());
    put_digest_bytes(&mut hash, intent.workspace_id.to_string().as_bytes());
    put_digest_bytes(&mut hash, intent.command_id.to_string().as_bytes());
    put_digest_bytes(&mut hash, intent.idempotency_key.as_bytes());
    hash.update([mode_tag(intent.requested_mode)]);
    hash.update(intent.preset_version.to_be_bytes());
    hash.update(intent.expected_authorization_revision.to_be_bytes());
    match intent.expires_at_unix_ms {
        Some(expiry) => {
            hash.update([1]);
            hash.update(expiry.to_be_bytes());
        }
        None => hash.update([0]),
    }
    hex::encode(hash.finalize())
}

fn make_recovery_record(
    intent: &PermissionModeSetIntent,
    stable: StableRuntimeIdentity,
    audit: RuntimeAuditSnapshot,
) -> Result<Vec<u8>, RecoveryError> {
    stable.validate()?;
    audit.validate()?;
    let record = PermissionRecoveryRecordV1 {
        record_version: RECOVERY_RECORD_VERSION,
        contract_version: RECOVERY_CONTRACT_VERSION,
        command_id: intent.command_id,
        idempotency_key: intent.idempotency_key.clone(),
        workspace_id: intent.workspace_id,
        requested_mode: intent.requested_mode,
        preset_version: intent.preset_version,
        expected_authorization_revision: intent.expected_authorization_revision,
        expires_at_unix_ms: intent.expires_at_unix_ms,
        scope_digest: scope_digest(&stable),
        intent_digest: local_intent_digest(intent, &stable),
        stable_runtime: stable,
        audit,
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| RecoveryError::Io)?;
    (bytes.len() <= MAX_RECOVERY_RECORD_BYTES)
        .then_some(bytes)
        .ok_or(RecoveryError::Io)
}

fn decode_recovery_record(bytes: &[u8]) -> Result<PermissionRecoveryRecordV1, RecoveryError> {
    if bytes.is_empty() || bytes.len() > MAX_RECOVERY_RECORD_BYTES {
        return Err(RecoveryError::Corrupt);
    }
    let record: PermissionRecoveryRecordV1 =
        serde_json::from_slice(bytes).map_err(|_| RecoveryError::Corrupt)?;
    record
        .stable_runtime
        .validate()
        .map_err(|_| RecoveryError::Corrupt)?;
    record
        .audit
        .validate()
        .map_err(|_| RecoveryError::Corrupt)?;
    let key_identity = runne_runtime_client::CommandIdentity::new(
        record.command_id,
        record.idempotency_key.clone(),
    )
    .map_err(|_| RecoveryError::Corrupt)?;
    drop(key_identity);
    let scope = scope_digest(&record.stable_runtime);
    let digest = intent_digest_from_record(&record);
    if record.record_version != RECOVERY_RECORD_VERSION
        || record.contract_version != RECOVERY_CONTRACT_VERSION
        || record.preset_version != 1
        || record.expected_authorization_revision > i64::MAX as u64
        || record.expires_at_unix_ms.is_some_and(|expiry| expiry <= 0)
        || record.scope_digest != scope
        || record.intent_digest != digest
        || canonical_digest(&record.intent_digest).is_err()
    {
        return Err(RecoveryError::Corrupt);
    }
    Ok(record)
}

fn intent_digest_from_record(record: &PermissionRecoveryRecordV1) -> String {
    let intent = PermissionModeSetIntent {
        workspace_id: record.workspace_id,
        command_id: record.command_id,
        idempotency_key: record.idempotency_key.clone(),
        requested_mode: record.requested_mode,
        expected_authorization_revision: record.expected_authorization_revision,
        preset_version: record.preset_version,
        expires_at_unix_ms: record.expires_at_unix_ms,
    };
    local_intent_digest(&intent, &record.stable_runtime)
}

fn match_recovery_record(
    record: &PermissionRecoveryRecordV1,
    intent: &PermissionModeSetIntent,
    stable: &StableRuntimeIdentity,
) -> Result<(), CliError> {
    if record.stable_runtime != *stable {
        return Err(CliError::PermissionRecoveryScopeMismatch(intent.command_id));
    }
    if record.command_id != intent.command_id
        || record.workspace_id != intent.workspace_id
        || record.idempotency_key != intent.idempotency_key
        || record.requested_mode != intent.requested_mode
        || record.preset_version != intent.preset_version
        || record.expected_authorization_revision != intent.expected_authorization_revision
        || record.expires_at_unix_ms != intent.expires_at_unix_ms
        || record.intent_digest != local_intent_digest(intent, stable)
    {
        return Err(CliError::PermissionRecoveryConflict(intent.command_id));
    }
    Ok(())
}

fn put_digest_bytes(hash: &mut Sha256, value: &[u8]) {
    // Callers provide validated IDs and intent fields, each bounded to at most 256 bytes.
    let length = u32::try_from(value.len())
        .expect("validated permission intent field fits the digest length prefix");
    hash.update(length.to_be_bytes());
    hash.update(value);
}

const fn mode_tag(mode: runne_runtime_client::PermissionModeV1) -> u8 {
    match mode {
        runne_runtime_client::PermissionModeV1::AskAlways => 1,
        runne_runtime_client::PermissionModeV1::RiskBased => 2,
        runne_runtime_client::PermissionModeV1::FullAccess => 3,
    }
}
