use std::collections::BTreeMap;

use gocode_platform_ports::process::{
    HeldProcessTreeHandleV1, MonotonicDeadline, NoProcessStartedEvidenceV1, ProcessAttemptIdV1,
    ProcessGenerationIdV1, ProcessLifecycleBindingV1, ProcessOwnerIdV1, ProcessSessionIdV1,
    ProcessTerminalDispositionV1, ProcessTerminalEvidenceV1,
};
use sha2::{Digest, Sha256};

use crate::EffectAdmission;

use super::{
    ProcessAuditRecordV1, ProcessAuditStageV1, ProcessClaimBindingV1, ProcessClaimInputV1,
    ProcessClaimJournalMemoryV1, ProcessClaimJournalPort, ProcessClaimKeyV1, ProcessClaimRecordV1,
    ProcessContractErrorV1, ProcessLifecycleStateV1, ProcessMonotonicTimingDispositionV1,
    ProcessOwnerVerificationV1, ProcessSettlementProofV1, ProcessTerminalSettlementV1,
    ProcessTreeCleanupV1, ProcessUncertainReasonV1,
    journal::{project_claim, settle, transition},
};

#[derive(Default)]
struct Journal {
    records: BTreeMap<String, ProcessClaimRecordV1>,
    reject_replacement: bool,
}

impl ProcessClaimJournalPort for Journal {
    fn read(
        &self,
        key: &ProcessClaimKeyV1,
    ) -> Result<Option<ProcessClaimRecordV1>, ProcessContractErrorV1> {
        Ok(self.records.get(key.permit_id()).cloned())
    }

    fn compare_and_set(
        &mut self,
        key: &ProcessClaimKeyV1,
        expected: Option<&ProcessClaimRecordV1>,
        replacement: ProcessClaimRecordV1,
    ) -> Result<bool, ProcessContractErrorV1> {
        if self.reject_replacement || self.records.get(key.permit_id()) != expected {
            return Ok(false);
        }
        self.records.insert(key.permit_id().to_owned(), replacement);
        Ok(true)
    }
}

fn input() -> ProcessClaimInputV1 {
    ProcessClaimInputV1::new(
        &EffectAdmission {
            permit_id: "settlement-permit".to_owned(),
        },
        [1; 32],
        ProcessClaimBindingV1::new([2; 16], [3; 16], [4; 16], [5; 16], [6; 16])
            .expect("valid binding"),
        MonotonicDeadline::checked_after(1, 1).expect("valid deadline"),
    )
    .expect("valid admission")
}

fn lifecycle() -> ProcessLifecycleBindingV1 {
    ProcessLifecycleBindingV1::new(
        ProcessOwnerIdV1::new([2; 16]).expect("owner"),
        ProcessAttemptIdV1::new([3; 16]).expect("attempt"),
        ProcessSessionIdV1::new([4; 16]).expect("session"),
        ProcessGenerationIdV1::new([5; 16]).expect("generation"),
        HeldProcessTreeHandleV1::new([6; 16]).expect("tree"),
    )
}

fn empty_digest() -> [u8; 32] {
    Sha256::digest([]).into()
}

fn launch(journal: &mut Journal, input: &ProcessClaimInputV1) {
    project_claim(journal, input).expect("claim projection");
    transition(journal, input, ProcessLifecycleStateV1::Launching).expect("launch transition");
}

fn running(journal: &mut Journal, input: &ProcessClaimInputV1) {
    launch(journal, input);
    transition(journal, input, ProcessLifecycleStateV1::Running).expect("running transition");
}

fn settlement(
    input: &ProcessClaimInputV1,
    proof: ProcessSettlementProofV1,
) -> ProcessTerminalSettlementV1 {
    settlement_with_output(input, proof, super::ProcessOutputEvidenceV1::empty())
}

fn settlement_with_output(
    input: &ProcessClaimInputV1,
    proof: ProcessSettlementProofV1,
    output: super::ProcessOutputEvidenceV1,
) -> ProcessTerminalSettlementV1 {
    let (owner, cleanup) = match &proof {
        ProcessSettlementProofV1::NotStarted(_) => (
            ProcessOwnerVerificationV1::NotApplicable,
            ProcessTreeCleanupV1::NotApplicable,
        ),
        ProcessSettlementProofV1::Completed(_) => (
            ProcessOwnerVerificationV1::Verified,
            ProcessTreeCleanupV1::Verified,
        ),
        ProcessSettlementProofV1::Uncertain(_) => (
            ProcessOwnerVerificationV1::Unavailable,
            ProcessTreeCleanupV1::Unavailable,
        ),
    };
    ProcessTerminalSettlementV1::new(
        input.binding(),
        proof,
        output,
        ProcessMonotonicTimingDispositionV1::WithinDeadline,
        cleanup,
        owner,
    )
    .expect("valid settlement")
}

#[test]
fn terminal_settlement_atomically_contains_output_metadata() {
    let input = input();
    let mut journal = Journal::default();
    running(&mut journal, &input);
    let proof = ProcessSettlementProofV1::Completed(
        ProcessTerminalEvidenceV1::new(
            &lifecycle(),
            ProcessTerminalDispositionV1::Completed,
            ProcessOwnerVerificationV1::Verified,
            ProcessTreeCleanupV1::Verified,
            [7; 32],
        )
        .expect("terminal evidence"),
    );
    let record = settle(&mut journal, &input, settlement(&input, proof)).expect("settled");
    let metadata = record.settlement().expect("settlement metadata");

    assert_eq!(record.state(), ProcessLifecycleStateV1::Completed);
    assert_eq!(metadata.output().stdout().digest(), empty_digest());
    assert_eq!(metadata.output().stderr().byte_count(), 0);
    assert!(!metadata.output().stdout().truncated());
    assert_eq!(
        metadata.timing(),
        ProcessMonotonicTimingDispositionV1::WithinDeadline
    );
    assert_eq!(metadata.tree_cleanup(), ProcessTreeCleanupV1::Verified);
    assert_eq!(
        metadata.owner_verification(),
        ProcessOwnerVerificationV1::Verified
    );
    assert_eq!((metadata.revision(), metadata.sequence()), (4, 1));
}

#[test]
fn not_started_is_atomically_settled_with_empty_output_metadata() {
    let input = input();
    let mut journal = Journal::default();
    launch(&mut journal, &input);
    let proof = ProcessSettlementProofV1::NotStarted(
        NoProcessStartedEvidenceV1::new(&lifecycle(), [8; 32]).expect("no-start evidence"),
    );

    let record = settle(&mut journal, &input, settlement(&input, proof)).expect("settled");
    let metadata = record.settlement().expect("settlement metadata");

    assert_eq!(record.state(), ProcessLifecycleStateV1::NotStarted);
    assert_eq!(metadata.output().stdout().byte_count(), 0);
    assert_eq!(metadata.output().stderr().digest(), empty_digest());
}

#[test]
fn uncertain_is_atomically_settled_with_typed_reason() {
    let input = input();
    let mut journal = Journal::default();
    launch(&mut journal, &input);
    let proof = ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::EvidenceUnavailable);

    let record = settle(&mut journal, &input, settlement(&input, proof.clone())).expect("settled");

    assert_eq!(record.state(), ProcessLifecycleStateV1::Uncertain);
    assert_eq!(record.settlement().expect("settlement").proof(), &proof);
}

#[test]
fn failed_cas_leaves_nonterminal_state_without_settlement() {
    let input = input();
    let mut journal = Journal::default();
    launch(&mut journal, &input);
    journal.reject_replacement = true;

    assert_eq!(
        settle(
            &mut journal,
            &input,
            settlement(
                &input,
                ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::EvidenceUnavailable),
            ),
        ),
        Err(ProcessContractErrorV1::ClaimProjectionConflict)
    );
    let record = journal
        .records
        .get(input.key().permit_id())
        .expect("prior record");
    assert_eq!(record.state(), ProcessLifecycleStateV1::Launching);
    assert_eq!(record.settlement(), None);
}

#[test]
fn exact_settlement_replay_is_idempotent_and_conflict_is_rejected() {
    let input = input();
    let mut journal = Journal::default();
    launch(&mut journal, &input);
    let original = settlement(
        &input,
        ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::EvidenceUnavailable),
    );

    let first = settle(&mut journal, &input, original.clone()).expect("first settlement");
    let replay = settle(&mut journal, &input, original).expect("idempotent replay");
    assert_eq!(first.settlement(), replay.settlement());
    assert_eq!(
        settle(
            &mut journal,
            &input,
            settlement(
                &input,
                ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::TimingUnavailable),
            ),
        ),
        Err(ProcessContractErrorV1::SettlementConflict)
    );
    assert_eq!(
        settle(
            &mut journal,
            &input,
            settlement_with_output(
                &input,
                ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::EvidenceUnavailable),
                super::ProcessOutputEvidenceV1::test_metadata([9; 32], 1, [0; 32], 0),
            ),
        ),
        Err(ProcessContractErrorV1::SettlementConflict)
    );
    assert_eq!(
        journal
            .records
            .get(input.key().permit_id())
            .expect("original record")
            .settlement(),
        first.settlement()
    );
}

#[test]
fn memory_journal_keeps_exact_settlement_and_rejects_a_different_draft() {
    let input = input();
    let mut journal = ProcessClaimJournalMemoryV1::new();
    project_claim(&mut journal, &input).expect("claim projection");
    transition(&mut journal, &input, ProcessLifecycleStateV1::Launching).expect("launching");
    let original = settlement(
        &input,
        ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::EvidenceUnavailable),
    );

    let first = settle(&mut journal, &input, original.clone()).expect("first settlement");
    let replay = settle(&mut journal, &input, original).expect("exact settlement replay");
    assert_eq!(first.settlement(), replay.settlement());
    assert_eq!(
        settle(
            &mut journal,
            &input,
            settlement(
                &input,
                ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::TimingUnavailable),
            ),
        ),
        Err(ProcessContractErrorV1::SettlementConflict)
    );
}

#[test]
fn raw_transient_markers_absent_from_settlement_audit_debug() {
    let input = input();
    let settlement = settlement(
        &input,
        ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::EvidenceUnavailable),
    );
    let audit = ProcessAuditRecordV1::new(ProcessAuditStageV1::Uncertain, settlement.clone());

    assert_eq!(
        format!("{settlement:?}"),
        "ProcessTerminalSettlementV1(redacted)"
    );
    assert_eq!(format!("{audit:?}"), "ProcessAuditRecordV1(redacted)");
}
