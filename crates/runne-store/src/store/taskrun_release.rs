use super::*;
use runne_application::ports::{
    TaskRunClaimReceipt, TaskRunFence, TaskRunNoEffectReleaseError as Error,
    TaskRunNoEffectReleasePort, TaskRunNoEffectReleaseReceipt, TaskRunNoEffectReleaseRequest,
    TaskRunNoEffectReleaseResult,
};
use rusqlite::TransactionBehavior;

type OccupationRow = (Vec<u8>, Vec<u8>, i64, i64, String, String);
type ReleaseReceiptRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
);
type ReleasedEventRow = (String, Option<Vec<u8>>, i64, Vec<u8>, Vec<u8>, Vec<u8>);

impl TaskRunNoEffectReleasePort for StoreTransaction {
    fn release_taskrun_no_effect(
        &self,
        request: TaskRunNoEffectReleaseRequest,
    ) -> Result<TaskRunNoEffectReleaseResult, Error> {
        let scope = encode_scope(&request)?;
        let mut writer = self.inner.writer.lock().map_err(|_| Error::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        if let Some(receipt) = duplicate(&tx, &request, &scope)? {
            tx.commit().map_err(|_| Error::Unavailable)?;
            return Ok(TaskRunNoEffectReleaseResult::Duplicate(receipt));
        }
        if command_used(&tx, request.command_id)? {
            return Err(Error::IdempotencyConflict);
        }
        if request.idempotency_scope.operation != OperationTag::TaskRunNoEffectRelease
            || request.idempotency_scope.aggregate_scope
                != (AggregateScope::ExistingTaskRun {
                    taskrun_id: request.identity.taskrun_id,
                })
            || request.failure_event.command_id() != &request.command_id
            || request.failure_event.idempotency_key() != &request.idempotency_key
            || request.failure_event.aggregate_id()
                != &AggregateId::TaskRun(request.identity.taskrun_id)
            || request.failure_event.payload()
                != &(TaskRunEvent::TaskRunFailed {
                    reason: "dispatch_not_started".into(),
                })
        {
            return Err(Error::CorruptData);
        }
        let id = &request.identity;
        let node = uuid::Uuid::parse_str(&id.node_id.0).map_err(|_| Error::StaleAssignment)?;
        if node.is_nil()
            || node.to_string() != id.node_id.0
            || id.node_epoch == 0
            || id.fence.0 == 0
        {
            return Err(Error::StaleAssignment);
        }
        let row: Option<OccupationRow> = tx.query_row("SELECT attempt_id,node_id,node_epoch,lease_expires_at_ms,state,dispatch_intent FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2", params![id.taskrun_id.as_bytes(),i64::try_from(id.fence.0).map_err(|_| Error::StaleAssignment)?], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(|_| Error::CorruptData)?;
        let Some((attempt, stored_node, epoch, _expiry, state, intent)) = row else {
            return Err(Error::StaleAssignment);
        };
        if attempt.as_slice() != id.attempt_id.as_bytes()
            || stored_node.as_slice() != node.as_bytes()
            || epoch != id.node_epoch as i64
            || state != "active"
        {
            return Err(Error::StaleAssignment);
        }
        let ledger: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?2",
                params![id.taskrun_id.as_bytes(), id.fence.0 as i64],
                |r| r.get(0),
            )
            .map_err(|_| Error::CorruptData)?;
        if intent != "absent" || ledger != 0 {
            return Err(Error::DispatchMayHaveStarted);
        }
        super::taskrun_no_effect_proof::require_no_generation_evidence(
            &tx,
            id.taskrun_id,
            id.attempt_id,
            &self.runtime_authority_id,
        )?;
        let provider_evidence: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_provider_bindings
                               WHERE taskrun_id=?1)
                  OR EXISTS(SELECT 1 FROM provider_execution_admissions
                             WHERE taskrun_id=?1)",
                [id.taskrun_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| Error::CorruptData)?;
        if provider_evidence {
            return Err(Error::DispatchMayHaveStarted);
        }
        super::taskrun_claim::verify_active_assignment(&tx, id)
            .map_err(|_| Error::StaleAssignment)?;
        let current: i64 = tx.query_row("SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1", [id.taskrun_id.as_bytes()], |r| r.get(0)).map_err(|_| Error::CorruptData)?;
        let claim_version: i64 = tx
            .query_row(
                "SELECT new_version FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2",
                params![id.taskrun_id.as_bytes(), id.fence.0 as i64],
                |r| r.get(0),
            )
            .map_err(|_| Error::CorruptData)?;
        let current_version = u64::try_from(current).map_err(|_| Error::CorruptData)?;
        if current_version != request.expected_version {
            return Err(Error::StaleVersion {
                expected: request.expected_version,
                actual: current_version,
            });
        }
        if current != claim_version {
            return Err(Error::StaleVersion {
                expected: claim_version as u64,
                actual: current_version,
            });
        }
        let last_event: Vec<u8> = tx
            .query_row("SELECT last_event_id FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1", [id.taskrun_id.as_bytes()], |r| r.get(0))
            .map_err(|_| Error::CorruptData)?;
        if request
            .failure_event
            .causation_id()
            .map(|event| event.as_bytes().as_slice())
            != Some(last_event.as_slice())
        {
            return Err(Error::CorruptData);
        }
        let (now, last_timestamp): (i64, Option<i64>) = tx
            .query_row(
                "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER),(SELECT last_timestamp FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1)",
                [id.taskrun_id.as_bytes()],
                |r| Ok((r.get(0)?,r.get(1)?)),
            )
            .map_err(|_| Error::Unavailable)?;
        tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='no_effect_terminal',updated_at=?1
             WHERE taskrun_id=?2 AND state IN ('preflight','approval_pending','approved')
               AND attempt_id IS NULL AND managed_area_identity IS NULL",
            params![now, id.taskrun_id.as_bytes()],
        )
        .map_err(|_| Error::CorruptData)?;
        let position: i64 = tx
            .query_row(
                "SELECT next_global_position FROM event_log_state WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(|_| Error::CorruptData)?;
        let next = current.checked_add(1).ok_or(Error::CorruptData)?;
        let micros = now.checked_mul(1000).ok_or(Error::CorruptData)?;
        let micros = micros.max(last_timestamp.ok_or(Error::CorruptData)?);
        crate::store::event_guard::append_taskrun_event(
            &tx,
            self.prohibited_content.as_ref(),
            &request.failure_event,
            next as u64,
            position,
            micros,
        )
        .map_err(|_| Error::CorruptData)?;
        if tx.execute("UPDATE aggregate_streams SET current_version=?1,last_event_id=?2,last_timestamp=?3 WHERE aggregate_type=1 AND aggregate_id=?4 AND current_version=?5", params![next,request.failure_event.event_id().as_bytes(),micros,id.taskrun_id.as_bytes(),current]).map_err(|_| Error::CorruptData)?!=1 { return Err(Error::StaleVersion { expected:current as u64, actual:current as u64 }); }
        crate::store::snapshot::refresh_aggregate_snapshot(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            id.taskrun_id.as_bytes(),
        )
        .map_err(|_| Error::CorruptData)?;
        if tx.execute("UPDATE event_log_state SET next_global_position=?1 WHERE singleton=1 AND next_global_position=?2", params![position.checked_add(1).ok_or(Error::CorruptData)?,position]).map_err(|_| Error::CorruptData)?!=1 { return Err(Error::CorruptData); }
        if tx.execute("UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1 WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6 AND state='active' AND dispatch_intent='absent'", params![request.failure_event.event_id().as_bytes(),id.taskrun_id.as_bytes(),id.fence.0 as i64,id.attempt_id.as_bytes(),node.as_bytes(),id.node_epoch as i64]).map_err(|_| Error::CorruptData)?!=1 { return Err(Error::StaleAssignment); }
        let receipt = TaskRunNoEffectReleaseReceipt {
            taskrun_id: id.taskrun_id,
            attempt_id: id.attempt_id,
            fence: id.fence,
            failure_event_id: *request.failure_event.event_id(),
            new_version: next as u64,
        };
        tx.execute("INSERT INTO taskrun_no_effect_release_receipts(command_id,idempotency_scope,idempotency_key,fingerprint,taskrun_id,attempt_id,fence,failure_event_id,new_version) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![request.command_id.as_bytes(),scope,request.idempotency_key.as_str().as_bytes(),request.command_fingerprint.as_bytes(),id.taskrun_id.as_bytes(),id.attempt_id.as_bytes(),id.fence.0 as i64,request.failure_event.event_id().as_bytes(),next]).map_err(|_| Error::IdempotencyConflict)?;
        tx.commit().map_err(|_| Error::Unavailable)?;
        Ok(TaskRunNoEffectReleaseResult::Released(receipt))
    }
}

fn encode_scope(request: &TaskRunNoEffectReleaseRequest) -> Result<Vec<u8>, Error> {
    if request.idempotency_scope.operation != OperationTag::TaskRunNoEffectRelease
        || request.idempotency_scope.aggregate_scope
            != (AggregateScope::ExistingTaskRun {
                taskrun_id: request.identity.taskrun_id,
            })
    {
        return Err(Error::IdempotencyConflict);
    }
    IdempotencyScopeCodec
        .encode(&request.idempotency_scope)
        .map_err(|_| Error::CorruptData)
}

fn command_used(tx: &rusqlite::Transaction<'_>, id: CommandId) -> Result<bool, Error> {
    tx.query_row("SELECT EXISTS(SELECT 1 FROM command_receipts WHERE command_id=?1) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=?1) OR EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id=?1) OR EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=?1)", [id.as_bytes()], |r| r.get(0)).map_err(|_| Error::CorruptData)
}

fn duplicate(
    tx: &rusqlite::Transaction<'_>,
    req: &TaskRunNoEffectReleaseRequest,
    scope: &[u8],
) -> Result<Option<TaskRunNoEffectReleaseReceipt>, Error> {
    let row: Option<ReleaseReceiptRow> = tx.query_row("SELECT idempotency_scope,idempotency_key,fingerprint,taskrun_id,attempt_id,fence,failure_event_id,new_version FROM taskrun_no_effect_release_receipts WHERE command_id=?1", [req.command_id.as_bytes()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional().map_err(|_| Error::CorruptData)?;
    let Some((s, k, f, t, a, n, e, v)) = row else {
        return Ok(None);
    };
    if s != scope
        || k != req.idempotency_key.as_str().as_bytes()
        || f != req.command_fingerprint.as_bytes()
        || t.as_slice() != req.identity.taskrun_id.as_bytes()
        || a.as_slice() != req.identity.attempt_id.as_bytes()
        || n != req.identity.fence.0 as i64
    {
        return Err(Error::IdempotencyConflict);
    }
    let event_id = EventId::from_bytes(e.try_into().map_err(|_| Error::CorruptData)?);
    let (state,release,seq,command,key,payload): ReleasedEventRow = tx.query_row("SELECT o.state,o.release_event_id,e.sequence,e.command_id,e.idempotency_key,e.payload FROM taskrun_assignment_occupations o JOIN events e ON e.event_id=o.release_event_id WHERE o.taskrun_id=?1 AND o.fence=?2", params![t,n], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).map_err(|_| Error::CorruptData)?;
    let decoded = TaskRunEventCodec
        .decode(&payload)
        .map_err(|_| Error::CorruptData)?;
    if state != "released"
        || release.as_deref() != Some(event_id.as_bytes())
        || seq != v
        || command.as_slice() != req.command_id.as_bytes()
        || key != req.idempotency_key.as_str().as_bytes()
        || decoded
            != (TaskRunEvent::TaskRunFailed {
                reason: "dispatch_not_started".into(),
            })
    {
        return Err(Error::CorruptData);
    }
    let claim: (Vec<u8>,Vec<u8>,i64,i64,Vec<u8>,Vec<u8>) = tx.query_row("SELECT command_id,idempotency_key,lease_expires_at_ms,new_version,admitted_event_id,started_event_id FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2", params![t,n], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).map_err(|_| Error::CorruptData)?;
    let claim_id = CommandId::from_bytes(claim.0.try_into().map_err(|_| Error::CorruptData)?);
    let claim_key = claim.1;
    let claim_receipt = TaskRunClaimReceipt {
        taskrun_id: req.identity.taskrun_id,
        attempt_id: req.identity.attempt_id,
        node_id: req.identity.node_id.clone(),
        node_epoch: req.identity.node_epoch,
        fence: TaskRunFence(req.identity.fence.0),
        lease_expires_at: Timestamp::from_unix_micros(
            claim.2.checked_mul(1000).ok_or(Error::CorruptData)?,
        ),
        new_version: u64::try_from(claim.3).map_err(|_| Error::CorruptData)?,
        admitted_event_id: EventId::from_bytes(claim.4.try_into().map_err(|_| Error::CorruptData)?),
        started_event_id: EventId::from_bytes(claim.5.try_into().map_err(|_| Error::CorruptData)?),
    };
    super::taskrun_claim::verify_released_stream(
        tx,
        &claim_receipt,
        claim_id,
        &claim_key,
        event_id,
        u64::try_from(v).map_err(|_| Error::CorruptData)?,
        super::taskrun_claim::ReleaseEventMetadata {
            command_id: req.command_id,
            idempotency_key: req.idempotency_key.as_str().as_bytes(),
        },
    )
    .map_err(|_| Error::CorruptData)?;
    Ok(Some(TaskRunNoEffectReleaseReceipt {
        taskrun_id: req.identity.taskrun_id,
        attempt_id: req.identity.attempt_id,
        fence: req.identity.fence,
        failure_event_id: event_id,
        new_version: u64::try_from(v).map_err(|_| Error::CorruptData)?,
    }))
}
