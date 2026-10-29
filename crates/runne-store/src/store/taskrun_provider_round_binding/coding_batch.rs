use super::super::taskrun_tool_invocation::ToolSourceRef;
use super::*;
use runne_application::ports::TaskRunProviderToolResultRef;
use runne_domain::id::IntegrityDigest;

pub(super) fn is_coding(
    tx: &rusqlite::Connection,
    task: runne_domain::id::TaskRunId,
) -> Result<bool, Error> {
    super::super::taskrun_tool_invocation::budget_policy::limits(tx, task)
        .map(|v| v.0 == 32)
        .map_err(|_| Error::CorruptData)
}

// Every result from the preceding provider terminal must settle before any continuation.
// Provider rounds and monotonically increasing effect proposal indexes are distinct.
pub(super) fn verify(
    tx: &rusqlite::Connection,
    request: &BindPreparedTaskRunProviderRoundEffect,
    authority: &str,
    already_bound: bool,
    now: i64,
) -> Result<usize, Error> {
    let previous = request.previous_tool_result.ok_or(Error::NotPrepared)?;
    let round = request
        .round_index
        .checked_sub(1)
        .ok_or(Error::NotPrepared)?;
    let mut statement=tx.prepare("SELECT proposal_index,semantic_digest,result_digest,source_refs,continuation_started FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND round_index=?4 ORDER BY proposal_index").map_err(|_|Error::CorruptData)?;
    type Row = (u32, Vec<u8>, Option<Vec<u8>>, Vec<u8>, bool);
    let rows: Vec<Row> = statement
        .query_map(
            params![
                request.identity.taskrun_id.as_bytes(),
                previous.attempt_id.as_bytes(),
                previous.cycle_id.as_bytes(),
                round
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .map_err(|_| Error::CorruptData)?
        .collect::<Result<_, _>>()
        .map_err(|_| Error::CorruptData)?;
    if !(1..=16).contains(&rows.len())
        || rows.last().map(|r| r.0) != Some(previous.proposal_index)
        || rows
            .windows(2)
            .any(|r| r[0].0.checked_add(1) != Some(r[1].0))
    {
        return Err(Error::IdempotencyConflict);
    }
    let (prior,prior_call):(Option<u32>,Vec<u8>)=tx.query_row("SELECT previous_proposal_index,call_id FROM taskrun_provider_round_bindings WHERE taskrun_id=?1 AND fence=?2 AND round_index=?3",
        params![request.identity.taskrun_id.as_bytes(),request.identity.fence.0 as i64,round],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|Error::IdempotencyConflict)?;
    if rows.first().map(|r| r.0) != Some(prior.map_or(0, |n| n.saturating_add(1))) {
        return Err(Error::IdempotencyConflict);
    }
    let mut source_set = Vec::new();
    for (index, semantic, result, bytes, started) in &rows {
        if *started != already_bound {
            return Err(Error::IdempotencyConflict);
        }
        let semantic = IntegrityDigest::from_bytes(
            semantic
                .as_slice()
                .try_into()
                .map_err(|_| Error::CorruptData)?,
        );
        let result = IntegrityDigest::from_bytes(
            result
                .as_deref()
                .ok_or(Error::IdempotencyConflict)?
                .try_into()
                .map_err(|_| Error::CorruptData)?,
        );
        verify_previous_tool_permission(
            tx,
            authority,
            request.identity.taskrun_id,
            request.round_index,
            TaskRunProviderToolResultRef {
                attempt_id: previous.attempt_id,
                cycle_id: previous.cycle_id,
                proposal_index: *index,
                semantic_digest: semantic,
                result_digest: result,
            },
            &request.identity,
            now,
        )?;
        let sources: Vec<ToolSourceRef> =
            super::super::taskrun_tool_invocation::decode_sources(bytes)
                .map_err(|_| Error::CorruptData)?;
        source_set.push(sources);
    }
    verify_complete_sources(tx, &source_set)?;
    let dispatch = source_set[0][0].dispatch_attempt_id;
    let exact:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_execution_admissions WHERE dispatch_attempt_id=?1 AND call_id=?2 AND taskrun_id=?3 AND execution_attempt_id=?4)",params![dispatch.as_slice(),prior_call,request.identity.taskrun_id.as_bytes(),request.identity.attempt_id.as_bytes()],|r|r.get(0)).map_err(|_|Error::CorruptData)?;
    if !exact {
        return Err(Error::IdempotencyConflict);
    }
    Ok(rows.len())
}

fn verify_complete_sources(
    tx: &rusqlite::Connection,
    sets: &[Vec<ToolSourceRef>],
) -> Result<(), Error> {
    let first = sets
        .first()
        .and_then(|s| s.iter().find(|s| s.event_kind == 5 && s.terminal))
        .ok_or(Error::IdempotencyConflict)?;
    let mut sequences = std::collections::BTreeSet::new();
    for sources in sets {
        if sources.len() != 2 || !sources.iter().any(|s| s == first) {
            return Err(Error::IdempotencyConflict);
        }
        let tool = sources
            .iter()
            .find(|s| s.event_kind == 4 && !s.terminal)
            .ok_or(Error::IdempotencyConflict)?;
        if tool.dispatch_attempt_id != first.dispatch_attempt_id
            || tool.sequence >= first.sequence
            || !sequences.insert(tool.sequence)
        {
            return Err(Error::IdempotencyConflict);
        }
    }
    let mut statement=tx.prepare("SELECT sequence FROM provider_stream_journal WHERE dispatch_attempt_id=?1 AND event_kind=4 AND terminal=0 ORDER BY sequence").map_err(|_|Error::CorruptData)?;
    let committed: std::collections::BTreeSet<u64> = statement
        .query_map([first.dispatch_attempt_id.as_slice()], |r| r.get(0))
        .map_err(|_| Error::CorruptData)?
        .collect::<Result<_, _>>()
        .map_err(|_| Error::CorruptData)?;
    if sequences != committed {
        return Err(Error::IdempotencyConflict);
    }
    Ok(())
}

pub(super) fn mark(
    tx: &rusqlite::Connection,
    request: &BindPreparedTaskRunProviderRoundEffect,
    now: i64,
    count: usize,
) -> Result<(), Error> {
    let previous = request.previous_tool_result.ok_or(Error::NotPrepared)?;
    let changed=tx.execute("UPDATE taskrun_tool_invocations SET continuation_started=1,updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND round_index=?5 AND continuation_started=0",
        params![now,request.identity.taskrun_id.as_bytes(),previous.attempt_id.as_bytes(),previous.cycle_id.as_bytes(),request.round_index-1]).map_err(|_|Error::CorruptData)?;
    if changed != count {
        return Err(Error::IdempotencyConflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(sequence: u64, kind: u8) -> ToolSourceRef {
        ToolSourceRef {
            dispatch_attempt_id: [1; 16],
            sequence,
            event_kind: kind,
            terminal: kind == 5,
            plaintext_digest: IntegrityDigest::from_bytes([2; 32]),
            profile_digest: IntegrityDigest::from_bytes([3; 32]),
            runtime_generation: 1,
        }
    }
    #[test]
    fn continuation_requires_every_committed_tool_exactly_once() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE provider_stream_journal(dispatch_attempt_id BLOB,sequence INTEGER,event_kind INTEGER,terminal INTEGER)").unwrap();
        for sequence in [1, 2] {
            db.execute(
                "INSERT INTO provider_stream_journal VALUES(?1,?2,4,0)",
                params![[1_u8; 16].as_slice(), sequence],
            )
            .unwrap();
        }
        let a = vec![source(1, 4), source(3, 5)];
        let b = vec![source(2, 4), source(3, 5)];
        assert!(verify_complete_sources(&db, &[a.clone()]).is_err());
        assert!(verify_complete_sources(&db, &[a.clone(), a.clone()]).is_err());
        let mut wrong = b.clone();
        wrong[1].dispatch_attempt_id = [9; 16];
        assert!(verify_complete_sources(&db, &[a.clone(), wrong]).is_err());
        assert!(verify_complete_sources(&db, &[a, b]).is_ok());
    }
}
