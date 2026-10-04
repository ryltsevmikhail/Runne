use super::super::super::*;
use super::super::validate::BoundSuccessor;
use runne_application::commands::CommandOutcome;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    CommitError, StorageFailureKind, UnknownSuccessorCommit, UnknownSuccessorCommitResult,
};
use rusqlite::{Transaction, params};

fn fail(kind: StorageFailureKind) -> CommitError {
    CommitError::StorageFailure(kind)
}

pub(super) fn write_command_receipt(
    tx: &Transaction<'_>,
    payload: &UnknownSuccessorCommit,
    scope: &[u8],
    result: UnknownSuccessorCommitResult,
    _conversation: ConversationId,
) -> Result<(), CommitError> {
    let outcome = CommandOutcome::UnknownSuccessorCreated {
        predecessor_taskrun_id: result.predecessor_taskrun_id,
        predecessor_version: result.predecessor_version,
        conversation_id: result.conversation_id,
        conversation_version: result.conversation_version,
        successor_taskrun_id: result.successor_taskrun_id,
        successor_version: result.successor_version,
    };
    let encoded = CommandOutcomeCodec
        .encode(&outcome)
        .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    tx.execute(
        "INSERT INTO command_receipts(command_id,idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome,committed_at)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            payload.command_id.as_bytes(),
            scope,
            payload.idempotency_key.as_str().as_bytes(),
            payload.command_fingerprint.as_bytes().as_slice(),
            encoded,
            now_micros(),
        ],
    )
    .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    Ok(())
}

pub(super) fn write_successor_receipt(
    tx: &Transaction<'_>,
    payload: &UnknownSuccessorCommit,
    bound: &BoundSuccessor,
    result: UnknownSuccessorCommitResult,
) -> Result<(), CommitError> {
    let input_digest = CommandFingerprint::for_submit(
        &bound.conversation_id,
        &bound.workspace_id,
        &bound.successor_input,
    );
    let predecessor_input_digest = CommandFingerprint::for_submit(
        &bound.conversation_id,
        &bound.workspace_id,
        &bound.original_input,
    );
    let model_ref = runne_provider::ModelRef::new(
        runne_provider::ProviderId::new(bound.provider_id.clone())
            .map_err(|_| fail(StorageFailureKind::CorruptData))?,
        bound.model_id.clone(),
        bound.model_revision.clone(),
    )
    .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"runne-unknown-successor-principal\x01");
    hasher.update((bound.origin_principal.len() as u64).to_be_bytes());
    hasher.update(bound.origin_principal.as_bytes());
    let principal_digest: [u8; 32] = hasher.finalize().into();
    let mut key_hash = sha2::Sha256::new();
    key_hash.update(b"runne-unknown-successor-idempotency\x01");
    key_hash.update((payload.idempotency_key.as_str().len() as u64).to_be_bytes());
    key_hash.update(payload.idempotency_key.as_str().as_bytes());
    let key_digest: [u8; 32] = key_hash.finalize().into();
    tx.execute(
        "INSERT INTO taskrun_unknown_successor_receipts(
         predecessor_taskrun_id,successor_taskrun_id,predecessor_attempt_id,predecessor_dispatch_attempt_id,
         predecessor_event_id,predecessor_event_version,conversation_id,generation_superseded_event_id,
         generation_superseded_version,successor_submit_event_id,successor_submit_version,workspace_id,
         principal_digest,principal_id,origin_kind,project_id,origin_operation,acknowledgement_code,
         acknowledgement_version,acknowledgement_digest,predecessor_input_digest,typed_input_digest,
         provider_id,profile_id,profile_digest,model_id,model_revision,model_ref_digest,occupation_fence,
         occupation_release_event_id,occupation_release_version,occupation_release_reason,command_id,
         idempotency_key_digest,command_fingerprint,created_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?12,?13,'canonical_workspace',?14,24,
         'duplicate_execution_and_cost_v1',1,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,
         ?26,?27,?28,?29,?30,?31)",
        params![
            payload.predecessor_taskrun_id.as_bytes(),
            payload.successor_taskrun_id.as_bytes(),
            bound.attempt_id.as_bytes(),
            bound.dispatch_attempt_id.as_slice(),
            bound.predecessor_event_id.as_bytes(),
            bound.predecessor_event_version as i64,
            result.conversation_id.as_bytes(),
            if bound.add_generation_marker { Some(payload.event_ids[1].as_bytes().as_slice()) } else { None },
            if bound.add_generation_marker { Some(result.conversation_version as i64) } else { None },
            payload.event_ids[2].as_bytes(),
            bound.workspace_id.as_bytes(),
            principal_digest.as_slice(),
            bound.origin_principal,
            bound.project_id.as_bytes(),
            payload.acknowledgement_digest.as_bytes().as_slice(),
            predecessor_input_digest.as_bytes().as_slice(),
            input_digest.as_bytes().as_slice(),
            bound.provider_id,
            bound.profile_id,
            bound.profile_digest.as_slice(),
            bound.model_id,
            bound.model_revision,
            model_ref.digest_v1().as_slice(),
            bound.fence,
            bound.release_event.as_slice(),
            bound.release_version,
            bound.release_reason,
            payload.command_id.as_bytes(),
            key_digest.as_slice(),
            payload.command_fingerprint.as_bytes().as_slice(),
            now_micros(),
        ],
    )
    .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    Ok(())
}
