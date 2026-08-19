use super::{
    ProcessClaimInputV1, ProcessClaimJournalPort, ProcessClaimRecordV1, ProcessContractErrorV1,
    ProcessLifecycleStateV1, ProcessMonotonicTimingDispositionV1, ProcessOutputEvidenceV1,
    ProcessOwnerVerificationV1, ProcessSettlementProofV1, ProcessTerminalSettlementV1,
    ProcessTreeCleanupV1, ProcessUncertainReasonV1,
};

/// Reopens a persisted projection without retrying any platform or output boundary.
pub(super) fn recover_after_reopen<J>(
    journal: &mut J,
    key: &super::ProcessClaimKeyV1,
) -> Result<Option<ProcessClaimRecordV1>, ProcessContractErrorV1>
where
    J: ProcessClaimJournalPort,
{
    let Some(expected) = journal.read(key)? else {
        return Ok(None);
    };
    if expected.settlement().is_some() {
        return Ok(Some(expected));
    }
    let mut replacement = expected.clone();
    let settlement = ProcessTerminalSettlementV1::new(
        replacement.binding(),
        ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::RecoveryRequired),
        ProcessOutputEvidenceV1::empty(),
        ProcessMonotonicTimingDispositionV1::TimingUncertain,
        ProcessTreeCleanupV1::Unavailable,
        ProcessOwnerVerificationV1::Unavailable,
    )?;
    if expected.state() == ProcessLifecycleStateV1::Claimed {
        replacement.recover_settlement(settlement)?;
    } else {
        replacement.commit_settlement(settlement)?;
    }
    journal
        .compare_and_set(key, Some(&expected), replacement.clone())?
        .then_some(Some(replacement))
        .ok_or(ProcessContractErrorV1::ClaimProjectionConflict)
}

pub(super) fn project_claim<J>(
    journal: &mut J,
    input: &ProcessClaimInputV1,
) -> Result<(ProcessClaimRecordV1, bool), ProcessContractErrorV1>
where
    J: ProcessClaimJournalPort,
{
    if let Some(record) = journal.read(input.key())? {
        return exact_record(record, input).map(|record| (record, false));
    }
    let record = ProcessClaimRecordV1::claimed(input);
    if journal.compare_and_set(input.key(), None, record.clone())? {
        return Ok((record, true));
    }
    journal
        .read(input.key())?
        .ok_or(ProcessContractErrorV1::ClaimProjectionConflict)
        .and_then(|record| exact_record(record, input).map(|record| (record, false)))
}

pub(super) fn transition<J>(
    journal: &mut J,
    input: &ProcessClaimInputV1,
    next: ProcessLifecycleStateV1,
) -> Result<ProcessClaimRecordV1, ProcessContractErrorV1>
where
    J: ProcessClaimJournalPort,
{
    replace_record(journal, input, |record| record.transition(next))
}

/// Commits one metadata-only terminal settlement through exactly one record CAS.
pub(super) fn settle<J>(
    journal: &mut J,
    input: &ProcessClaimInputV1,
    settlement: ProcessTerminalSettlementV1,
) -> Result<ProcessClaimRecordV1, ProcessContractErrorV1>
where
    J: ProcessClaimJournalPort,
{
    replace_record(journal, input, |record| {
        record.commit_settlement(settlement)
    })
}

fn replace_record<J, F>(
    journal: &mut J,
    input: &ProcessClaimInputV1,
    update: F,
) -> Result<ProcessClaimRecordV1, ProcessContractErrorV1>
where
    J: ProcessClaimJournalPort,
    F: FnOnce(&mut ProcessClaimRecordV1) -> Result<(), ProcessContractErrorV1>,
{
    let expected = journal
        .read(input.key())?
        .ok_or(ProcessContractErrorV1::AdmissionMissing)?;
    if expected.settlement().is_some() {
        let mut replay = exact_record(expected, input)?;
        update(&mut replay)?;
        return Ok(replay);
    }
    let mut replacement = exact_record(expected.clone(), input)?;
    update(&mut replacement)?;
    journal
        .compare_and_set(input.key(), Some(&expected), replacement.clone())?
        .then_some(replacement)
        .ok_or(ProcessContractErrorV1::ClaimProjectionConflict)
}

fn exact_record(
    record: ProcessClaimRecordV1,
    input: &ProcessClaimInputV1,
) -> Result<ProcessClaimRecordV1, ProcessContractErrorV1> {
    record
        .matches(input)
        .then_some(record)
        .ok_or(ProcessContractErrorV1::ClaimProjectionConflict)
}
