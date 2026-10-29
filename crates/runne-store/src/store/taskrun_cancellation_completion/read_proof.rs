//! Read-only proof of cancellation before any dispatch or assignment existed.
use super::*;
use sha2::{Digest as _, Sha256};

type HistoryRow = (i64, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Vec<u8>, Vec<u8>);
type ReceiptRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

pub(super) fn verify_completion(
    tx: &rusqlite::Transaction<'_>,
    task: TaskRunId,
    authority: &runne_application::ports::RuntimeAuthorityId,
    rows: &[HistoryRow],
    completion_actor: &runne_domain::event::Actor,
) -> Result<(), Error> {
    if rows.len() != 4
        || rows[3].2.as_deref() != Some(rows[2].1.as_slice())
        || rows[2].3 == rows[3].3
        || TaskRunEventCodec
            .decode(&rows[3].4)
            .map_err(|_| Error::CorruptData)?
            != TaskRunEvent::CancellationCompleted
    {
        return Err(Error::CorruptData);
    }
    let extra: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_fence_counters WHERE taskrun_id=?1)
          OR EXISTS(SELECT 1 FROM taskrun_provider_round_bindings WHERE taskrun_id=?1)
          OR EXISTS(SELECT 1 FROM taskrun_tool_invocations WHERE taskrun_id=?1)
          OR EXISTS(SELECT 1 FROM provider_remote_request_intents WHERE taskrun_id=?1)",
            [task.as_bytes()],
            |r| r.get(0),
        )
        .map_err(|_| Error::CorruptData)?;
    if extra {
        return Err(Error::AlreadyClaimed);
    }
    let submitted: Vec<u8> = tx
        .query_row(
            "SELECT idempotency_scope_bytes FROM command_receipts WHERE command_id=?1",
            [&rows[0].3],
            |r| r.get(0),
        )
        .map_err(|_| Error::CorruptData)?;
    let submitted = IdempotencyScopeCodec
        .decode(&submitted)
        .map_err(|_| Error::CorruptData)?;
    for (index, operation, outcome) in [
        (
            2,
            OperationTag::CancelTaskRun,
            runne_application::commands::CommandOutcome::TaskRunCancellationRequested {
                taskrun_id: task,
                new_version: 3,
            },
        ),
        (
            3,
            OperationTag::CompleteQueuedCancellation,
            runne_application::commands::CommandOutcome::TaskRunCancellationCompleted {
                taskrun_id: task,
                new_version: 4,
            },
        ),
    ] {
        let (scope, key, fingerprint, encoded): ReceiptRow = tx.query_row(
            "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome FROM command_receipts WHERE command_id=?1",
            [&rows[index].3], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).map_err(|_| Error::CorruptData)?;
        let scope = IdempotencyScopeCodec
            .decode(&scope)
            .map_err(|_| Error::CorruptData)?;
        let expected = if index == 2 {
            CommandFingerprint::for_cancel(&task, 2)
        } else {
            let mut digest = Sha256::new();
            digest.update(b"runne-taskrun-queued-cancellation-complete-v1");
            digest.update(task.as_bytes());
            digest.update(3_u64.to_be_bytes());
            CommandFingerprint::from_bytes(digest.finalize().into())
        };
        let principal_matches = scope.principal_id == submitted.principal_id
            || (index == 3
                && scope.principal_id.0 == "runne-runtime"
                && completion_actor.as_str() == "runne-runtime");
        if scope.runtime_authority_id != *authority
            || !principal_matches
            || scope.operation != operation
            || scope.aggregate_scope != (AggregateScope::ExistingTaskRun { taskrun_id: task })
            || key != rows[index].5
            || fingerprint != expected.as_bytes()
            || CommandOutcomeCodec
                .decode(&encoded)
                .map_err(|_| Error::CorruptData)?
                != outcome
        {
            return Err(Error::CorruptData);
        }
    }
    Ok(())
}
