use gocode_platform_ports::process::{
    NoProcessStartedEvidenceV1, ProcessOwnerVerificationV1, ProcessTerminalEvidenceV1,
    ProcessTreeCleanupV1,
};

use super::{
    ProcessClaimInputV1, ProcessClaimJournalPort, ProcessClaimRecordV1, ProcessContractErrorV1,
    ProcessDispatchOutcomeV1, ProcessMonotonicTimingDispositionV1, ProcessOutputBoundsV1,
    ProcessOutputCallerIdV1, ProcessOutputCollectorV1, ProcessOutputEvidenceV1,
    ProcessOutputSourcePortV1, ProcessSettlementProofV1, ProcessTerminalResultV1,
    ProcessTerminalSettlementV1, ProcessUncertainReasonV1, TransientProcessOutputChannelV1,
    journal::settle,
};

pub(super) fn replay_outcome(record: ProcessClaimRecordV1) -> ProcessDispatchOutcomeV1 {
    match record
        .settlement()
        .map(|settlement| settlement.proof().clone())
    {
        Some(ProcessSettlementProofV1::Completed(_)) => {
            ProcessDispatchOutcomeV1::Terminal(ProcessTerminalResultV1::replay(
                record.settlement().expect("completed settlement exists"),
            ))
        }
        _ => ProcessDispatchOutcomeV1::State(record.state()),
    }
}

pub(super) fn settle_not_started<J>(
    journal: &mut J,
    claim: &ProcessClaimInputV1,
    evidence: NoProcessStartedEvidenceV1,
    timing: ProcessMonotonicTimingDispositionV1,
) -> Result<ProcessDispatchOutcomeV1, ProcessContractErrorV1>
where
    J: ProcessClaimJournalPort,
{
    let record = settle(
        journal,
        claim,
        settlement(
            claim,
            ProcessSettlementProofV1::NotStarted(evidence),
            ProcessOutputEvidenceV1::empty(),
            timing,
        )?,
    )?;
    Ok(ProcessDispatchOutcomeV1::State(record.state()))
}

pub(super) fn settle_uncertain<J>(
    journal: &mut J,
    claim: &ProcessClaimInputV1,
    timing: ProcessMonotonicTimingDispositionV1,
    reason: ProcessUncertainReasonV1,
) -> Result<ProcessDispatchOutcomeV1, ProcessContractErrorV1>
where
    J: ProcessClaimJournalPort,
{
    let proof = ProcessSettlementProofV1::Uncertain(reason);
    let record = settle(
        journal,
        claim,
        settlement(claim, proof, ProcessOutputEvidenceV1::empty(), timing)?,
    )?;
    Ok(ProcessDispatchOutcomeV1::State(record.state()))
}

pub(super) fn settle_output_unavailable<J>(
    journal: &mut J,
    claim: &ProcessClaimInputV1,
    timing: ProcessMonotonicTimingDispositionV1,
) -> Result<ProcessDispatchOutcomeV1, ProcessContractErrorV1>
where
    J: ProcessClaimJournalPort,
{
    let proof =
        ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::OutputEvidenceUnavailable);
    let record = settle(
        journal,
        claim,
        settlement(claim, proof, ProcessOutputEvidenceV1::empty(), timing)?,
    )?;
    Ok(ProcessDispatchOutcomeV1::State(record.state()))
}

pub(super) fn settle_terminal<J>(
    journal: &mut J,
    claim: &ProcessClaimInputV1,
    evidence: ProcessTerminalEvidenceV1,
    output: ProcessOutputEvidenceV1,
    transient: TransientProcessOutputChannelV1,
    timing: ProcessMonotonicTimingDispositionV1,
) -> Result<ProcessDispatchOutcomeV1, ProcessContractErrorV1>
where
    J: ProcessClaimJournalPort,
{
    let record = settle(
        journal,
        claim,
        settlement(
            claim,
            ProcessSettlementProofV1::Completed(evidence),
            output,
            timing,
        )?,
    )?;
    if let Some(settlement) = record
        .settlement()
        .filter(|settlement| matches!(settlement.proof(), ProcessSettlementProofV1::Completed(_)))
    {
        return Ok(ProcessDispatchOutcomeV1::Terminal(
            ProcessTerminalResultV1::first(settlement, transient),
        ));
    }
    Ok(ProcessDispatchOutcomeV1::State(record.state()))
}

pub(super) fn collect_and_settle_terminal<J, S>(
    journal: &mut J,
    claim: &ProcessClaimInputV1,
    evidence: ProcessTerminalEvidenceV1,
    bounds: &ProcessOutputBoundsV1,
    caller: &ProcessOutputCallerIdV1,
    source: &mut S,
    timing: ProcessMonotonicTimingDispositionV1,
) -> Result<ProcessDispatchOutcomeV1, ProcessContractErrorV1>
where
    J: ProcessClaimJournalPort,
    S: ProcessOutputSourcePortV1,
{
    let captured = ProcessOutputCollectorV1::collect(bounds, caller, source);
    let Ok(captured) = captured else {
        return settle_output_unavailable(journal, claim, timing);
    };
    let (metadata, transient) = captured.into_evidence_and_transient();
    settle_terminal(journal, claim, evidence, metadata, transient, timing)
}

fn settlement(
    claim: &ProcessClaimInputV1,
    proof: ProcessSettlementProofV1,
    output: ProcessOutputEvidenceV1,
    timing: ProcessMonotonicTimingDispositionV1,
) -> Result<ProcessTerminalSettlementV1, ProcessContractErrorV1> {
    let (proof, owner_verification, tree_cleanup) = match proof {
        ProcessSettlementProofV1::NotStarted(evidence) => (
            ProcessSettlementProofV1::NotStarted(evidence),
            ProcessOwnerVerificationV1::NotApplicable,
            ProcessTreeCleanupV1::NotApplicable,
        ),
        ProcessSettlementProofV1::Completed(evidence)
            if evidence.owner_verification() == ProcessOwnerVerificationV1::Verified
                && evidence.tree_cleanup() == ProcessTreeCleanupV1::Verified =>
        {
            (
                ProcessSettlementProofV1::Completed(evidence),
                ProcessOwnerVerificationV1::Verified,
                ProcessTreeCleanupV1::Verified,
            )
        }
        ProcessSettlementProofV1::Completed(evidence) => {
            let reason = if evidence.tree_cleanup() != ProcessTreeCleanupV1::Verified {
                ProcessUncertainReasonV1::TreeCleanupUnverified
            } else {
                ProcessUncertainReasonV1::EvidenceUnavailable
            };
            (
                ProcessSettlementProofV1::Uncertain(reason),
                evidence.owner_verification(),
                evidence.tree_cleanup(),
            )
        }
        ProcessSettlementProofV1::Uncertain(reason) => (
            ProcessSettlementProofV1::Uncertain(reason),
            ProcessOwnerVerificationV1::Unavailable,
            ProcessTreeCleanupV1::Unavailable,
        ),
    };
    ProcessTerminalSettlementV1::new(
        claim.binding(),
        proof,
        output,
        timing,
        tree_cleanup,
        owner_verification,
    )
}
