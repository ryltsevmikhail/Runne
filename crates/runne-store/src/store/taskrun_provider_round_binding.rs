use super::taskrun_provider_binding::{
    binding_matches, binding_node_id, binding_now_ms, digest_version_value, ensure_present_intent,
    load_binding, map_assignment_error, validate_prepared_request, verify_prepared_metadata,
};
use super::*;
mod coding_batch;
type ExistingRoundBinding = (
    i64,
    i64,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
);
use runne_application::ports::{
    BindPreparedTaskRunProviderEffect, BindPreparedTaskRunProviderRoundEffect,
    TaskRunProviderBindingError as Error, TaskRunProviderBindingPort, TaskRunProviderBindingResult,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

impl TaskRunProviderBindingPort for StoreTransaction {
    fn bind_prepared_taskrun_provider_effect(
        &self,
        request: BindPreparedTaskRunProviderEffect,
    ) -> Result<TaskRunProviderBindingResult, Error> {
        let identity = &request.identity;
        let node = binding_node_id(identity)?;
        let call_id = request.prepared.call_id.as_bytes();
        let version = digest_version_value(request.prepared.call_digest_version);
        validate_prepared_request(&request.prepared)?;
        let mut writer = self.inner.writer.lock().map_err(|_| Error::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        let now = binding_now_ms(&tx)?;
        let occupation = super::taskrun_assignment::exact_occupation(&tx, identity, node)
            .map_err(map_assignment_error)?;
        super::taskrun_assignment::verify_current_claim(&tx, identity)
            .map_err(map_assignment_error)?;
        super::taskrun_assignment::ensure_live_local_node(&tx, identity, node, now)
            .map_err(map_assignment_error)?;
        if occupation.3 <= now {
            return Err(Error::LeaseExpired);
        }
        if occupation.4 != "active" {
            return Err(Error::StaleAssignment);
        }
        let claim_version: i64 = tx.query_row(
            "SELECT new_version FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5",
            params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64, identity.attempt_id.as_bytes(), node, identity.node_epoch as i64],
            |row| row.get(0),
        ).optional().map_err(|_| Error::CorruptData)?.ok_or(Error::StaleAssignment)?;
        let stream_version: Option<i64> = tx.query_row(
            "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [identity.taskrun_id.as_bytes()], |row| row.get(0),
        ).optional().map_err(|_| Error::CorruptData)?;
        if u64::try_from(claim_version).ok() != Some(request.expected_claim_version)
            || stream_version.and_then(|v| u64::try_from(v).ok())
                != Some(request.expected_claim_version)
        {
            return Err(Error::StaleVersion);
        }
        verify_prepared_metadata(&tx, identity, &request.prepared, version)?;
        let existing = load_binding(&tx, identity)?;
        if let Some(existing) = existing {
            if !binding_matches(
                &existing,
                identity,
                node,
                request.expected_claim_version,
                &request.prepared,
                version,
            ) {
                return Err(Error::IdempotencyConflict);
            }
            tx.commit().map_err(|_| Error::Unavailable)?;
            return Ok(TaskRunProviderBindingResult::Duplicate);
        }
        ensure_present_intent(&tx, identity, node, now, &occupation.5)?;
        tx.execute(
            "INSERT INTO taskrun_provider_bindings(taskrun_id,fence,attempt_id,node_id,node_epoch,claim_version,call_id,call_digest_version,prepared_digest,render_digest,profile_digest,provider_idempotency_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![identity.taskrun_id.as_bytes(),identity.fence.0 as i64,identity.attempt_id.as_bytes(),node,identity.node_epoch as i64,request.expected_claim_version as i64,call_id,version,request.prepared.prepared_digest.as_slice(),request.prepared.render_digest.as_slice(),request.prepared.profile_digest.as_slice(),request.prepared.provider_idempotency_key],
        ).map_err(|_| Error::CorruptData)?;
        tx.commit().map_err(|_| Error::Unavailable)?;
        Ok(TaskRunProviderBindingResult::Bound)
    }

    fn bind_prepared_taskrun_provider_round_effect(
        &self,
        request: BindPreparedTaskRunProviderRoundEffect,
    ) -> Result<TaskRunProviderBindingResult, Error> {
        let mut writer = self.inner.writer.lock().map_err(|_| Error::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        let node = binding_node_id(&request.identity)?;
        let prev = request.previous_tool_result;
        let existing: Option<ExistingRoundBinding> = tx.query_row(
            "SELECT original_claim_version,current_taskrun_head,attempt_id,node_epoch,call_digest_version,prepared_digest,render_digest,profile_digest,provider_idempotency_key,previous_attempt_id,previous_cycle_id,previous_proposal_index,previous_semantic_digest,previous_result_digest,call_id,node_id FROM taskrun_provider_round_bindings WHERE taskrun_id=?1 AND fence=?2 AND round_index=?3",
            params![request.identity.taskrun_id.as_bytes(),request.identity.fence.0 as i64,request.round_index as i64], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?))).optional().map_err(|_|Error::CorruptData)?;
        if let Some(row) = existing {
            validate_d2_round(&tx, &request, true)?;
            if request.previous_tool_result.is_some()
                && coding_batch::is_coding(&tx, request.identity.taskrun_id)?
            {
                coding_batch::verify(
                    &tx,
                    &request,
                    &self.runtime_authority_id.0,
                    true,
                    binding_now_ms(&tx)?,
                )?;
            }
            verify_prepared_metadata(
                &tx,
                &request.identity,
                &request.prepared,
                digest_version_value(request.prepared.call_digest_version),
            )?;
            if row.0 != request.original_claim_version as i64
                || row.1 != request.current_taskrun_head as i64
                || row.2.as_slice() != request.identity.attempt_id.as_bytes()
                || row.3 != request.identity.node_epoch as i64
                || row.4 != digest_version_value(request.prepared.call_digest_version)
                || row.5.as_slice() != request.prepared.prepared_digest
                || row.6.as_slice() != request.prepared.render_digest
                || row.7.as_slice() != request.prepared.profile_digest
                || row.8 != request.prepared.provider_idempotency_key
                || row.9 != prev.map(|x| x.attempt_id.as_bytes().to_vec())
                || row.10 != prev.map(|x| x.cycle_id.as_bytes().to_vec())
                || row.11 != prev.map(|x| x.proposal_index as i64)
                || row.12 != prev.map(|x| x.semantic_digest.as_bytes().to_vec())
                || row.13 != prev.map(|x| x.result_digest.as_bytes().to_vec())
                || row.14.as_slice() != request.prepared.call_id.as_bytes()
                || row.15.as_slice() != node
            {
                return Err(Error::IdempotencyConflict);
            }
            tx.commit().map_err(|_| Error::Unavailable)?;
            return Ok(TaskRunProviderBindingResult::Duplicate);
        }
        validate_d2_round(&tx, &request, false)?;
        let now = binding_now_ms(&tx)?;
        if let Some(previous) = prev {
            verify_previous_tool_permission(
                &tx,
                &self.runtime_authority_id.0,
                request.identity.taskrun_id,
                request.round_index,
                previous,
                &request.identity,
                now,
            )?;
        }
        verify_prepared_metadata(
            &tx,
            &request.identity,
            &request.prepared,
            digest_version_value(request.prepared.call_digest_version),
        )?;
        let occupation = super::taskrun_assignment::exact_occupation(&tx, &request.identity, node)
            .map_err(map_assignment_error)?;
        if request.round_index == 0 {
            ensure_present_intent(&tx, &request.identity, node, now, &occupation.5)?;
        } else if occupation.5 != "present" {
            return Err(Error::StaleAssignment);
        } else {
            let intent_exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5 AND state='present')",
                    params![request.identity.taskrun_id.as_bytes(),request.identity.fence.0 as i64,request.identity.attempt_id.as_bytes(),node,request.identity.node_epoch as i64],
                    |row| row.get(0),
                )
                .map_err(|_| Error::CorruptData)?;
            if !intent_exists {
                return Err(Error::StaleAssignment);
            }
        }
        if let Some(previous) = prev {
            let coding = coding_batch::is_coding(&tx, request.identity.taskrun_id)?;
            if coding {
                let count =
                    coding_batch::verify(&tx, &request, &self.runtime_authority_id.0, false, now)?;
                coding_batch::mark(&tx, &request, now, count)?;
            } else {
                let changed = tx.execute(
                "UPDATE taskrun_tool_invocations SET continuation_started=1,updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND proposal_index=?5 AND semantic_digest=?6 AND result_digest=?7 AND state='result' AND result_truncated=0 AND local_stop_state=2 AND release_started=1 AND continuation_started=0 AND round_index=?8",
                params![now,request.identity.taskrun_id.as_bytes(),previous.attempt_id.as_bytes(),previous.cycle_id.as_bytes(),previous.proposal_index as i64,previous.semantic_digest.as_bytes(),previous.result_digest.as_bytes(),(request.round_index-1) as i64],
            ).map_err(|_| Error::CorruptData)?;
                if changed != 1 {
                    return Err(Error::IdempotencyConflict);
                }
            }
            let consumed = tx.execute(
                "UPDATE taskrun_tool_budgets SET continuations_used=continuations_used+1,updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND fence=?4 AND continuations_used=?5 AND continuations_used<continuations_limit",
                params![now,request.identity.taskrun_id.as_bytes(),request.identity.attempt_id.as_bytes(),request.identity.fence.0 as i64,(request.round_index-1) as i64],
            ).map_err(|_| Error::CorruptData)?;
            if consumed != 1 {
                return Err(Error::IdempotencyConflict);
            }
        }
        tx.execute("INSERT INTO taskrun_provider_round_bindings(taskrun_id,fence,round_index,attempt_id,node_id,node_epoch,original_claim_version,current_taskrun_head,call_id,call_digest_version,prepared_digest,render_digest,profile_digest,provider_idempotency_key,previous_attempt_id,previous_cycle_id,previous_proposal_index,previous_semantic_digest,previous_result_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)", params![request.identity.taskrun_id.as_bytes(),request.identity.fence.0 as i64,request.round_index as i64,request.identity.attempt_id.as_bytes(),node,request.identity.node_epoch as i64,request.original_claim_version as i64,request.current_taskrun_head as i64,request.prepared.call_id.as_bytes(),digest_version_value(request.prepared.call_digest_version),request.prepared.prepared_digest.as_slice(),request.prepared.render_digest.as_slice(),request.prepared.profile_digest.as_slice(),request.prepared.provider_idempotency_key,prev.map(|x|x.attempt_id.as_bytes().to_vec()),prev.map(|x|x.cycle_id.as_bytes().to_vec()),prev.map(|x|x.proposal_index as i64),prev.map(|x|x.semantic_digest.as_bytes().to_vec()),prev.map(|x|x.result_digest.as_bytes().to_vec())]).map_err(|_|Error::CorruptData)?;
        tx.commit().map_err(|_| Error::Unavailable)?;
        Ok(TaskRunProviderBindingResult::Bound)
    }

    fn verify_prepared_taskrun_provider_round_effect(
        &self,
        request: BindPreparedTaskRunProviderRoundEffect,
    ) -> Result<(), Error> {
        let mut writer = self.inner.writer.lock().map_err(|_| Error::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        validate_d2_round(&tx, &request, true)?;
        if let Some(previous) = request.previous_tool_result {
            verify_previous_tool_permission(
                &tx,
                &self.runtime_authority_id.0,
                request.identity.taskrun_id,
                request.round_index,
                previous,
                &request.identity,
                binding_now_ms(&tx)?,
            )?;
        }
        if request.previous_tool_result.is_some()
            && coding_batch::is_coding(&tx, request.identity.taskrun_id)?
        {
            coding_batch::verify(
                &tx,
                &request,
                &self.runtime_authority_id.0,
                true,
                binding_now_ms(&tx)?,
            )?;
        }
        let node = binding_node_id(&request.identity)?;
        let previous = request.previous_tool_result;
        let matches: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_provider_round_bindings
             WHERE taskrun_id=?1 AND fence=?2 AND round_index=?3
               AND original_claim_version=?4 AND current_taskrun_head=?5
               AND attempt_id=?6 AND node_id=?7 AND node_epoch=?8
               AND call_id=?9 AND call_digest_version=?10 AND prepared_digest=?11
               AND render_digest=?12 AND profile_digest=?13 AND provider_idempotency_key=?14
               AND previous_attempt_id IS ?15 AND previous_cycle_id IS ?16
               AND previous_proposal_index IS ?17 AND previous_semantic_digest IS ?18
               AND previous_result_digest IS ?19)",
                params![
                    request.identity.taskrun_id.as_bytes(),
                    request.identity.fence.0 as i64,
                    request.round_index as i64,
                    request.original_claim_version as i64,
                    request.current_taskrun_head as i64,
                    request.identity.attempt_id.as_bytes(),
                    node,
                    request.identity.node_epoch as i64,
                    request.prepared.call_id.as_bytes(),
                    digest_version_value(request.prepared.call_digest_version),
                    request.prepared.prepared_digest.as_slice(),
                    request.prepared.render_digest.as_slice(),
                    request.prepared.profile_digest.as_slice(),
                    request.prepared.provider_idempotency_key,
                    previous.map(|x| x.attempt_id.as_bytes().to_vec()),
                    previous.map(|x| x.cycle_id.as_bytes().to_vec()),
                    previous.map(|x| x.proposal_index as i64),
                    previous.map(|x| x.semantic_digest.as_bytes().to_vec()),
                    previous.map(|x| x.result_digest.as_bytes().to_vec()),
                ],
                |row| row.get(0),
            )
            .map_err(|_| Error::CorruptData)?;
        if !matches {
            return Err(Error::IdempotencyConflict);
        }
        verify_prepared_metadata(
            &tx,
            &request.identity,
            &request.prepared,
            digest_version_value(request.prepared.call_digest_version),
        )?;
        tx.commit().map_err(|_| Error::Unavailable)
    }
}

include!("taskrun_provider_round_binding/validation.rs");
