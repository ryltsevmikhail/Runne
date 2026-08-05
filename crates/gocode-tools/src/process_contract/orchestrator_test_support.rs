use std::{
    cell::Cell,
    collections::{BTreeMap, VecDeque},
};

use gocode_platform_ports::process::{
    HeldFileIdentityV1, HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessFileKindV1,
    ProcessGenerationIdV1, ProcessLifecycleBindingV1, ProcessOwnerIdV1, ProcessPlatformRequestV1,
    ProcessSessionIdV1, ProcessSymlinkProofV1, VerifiedCwdV1, VerifiedExecutableV1,
};

use crate::EffectAdmission;

use super::{
    ProcessCancellationTokenV1, ProcessClaimBindingV1, ProcessClaimJournalPort, ProcessClaimKeyV1,
    ProcessClaimRecordV1, ProcessContractErrorV1, ProcessMonotonicClockV1, ProcessOutputBoundsV1,
    ProcessOutputCallerIdV1, ProcessOutputReadBudgetV1, ProcessOutputSourceErrorV1,
    ProcessOutputSourceEventV1, ProcessOutputSourcePortV1, ProcessOutputStopEvidenceV1,
    ProcessOutputStopReasonV1, orchestrator_input::DispatchInputV1,
};

#[derive(Default)]
pub(super) struct Journal {
    pub(super) records: BTreeMap<String, ProcessClaimRecordV1>,
    terminal_commit_fails: bool,
    reject_terminal_cas: bool,
    commit_response_lost: bool,
    cas_attempts: u32,
}

impl Journal {
    pub(super) fn seeded() -> Self {
        Self::default()
    }

    pub(super) fn fail_terminal_commit(&mut self) {
        self.terminal_commit_fails = true;
    }

    pub(super) fn reject_terminal_cas(&mut self) {
        self.reject_terminal_cas = true;
    }

    pub(super) fn lose_terminal_commit_response(&mut self) {
        self.commit_response_lost = true;
    }

    pub(super) const fn cas_attempts(&self) -> u32 {
        self.cas_attempts
    }
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
        self.cas_attempts += 1;
        let terminal = replacement.settlement().is_some();
        if self.terminal_commit_fails && terminal {
            return Err(ProcessContractErrorV1::TerminalCommitFailed);
        }
        if self.reject_terminal_cas && terminal {
            return Ok(false);
        }
        if self.records.get(key.permit_id()) != expected {
            return Ok(false);
        }
        self.records.insert(key.permit_id().to_owned(), replacement);
        if terminal && self.commit_response_lost {
            self.commit_response_lost = false;
            return Err(ProcessContractErrorV1::TerminalCommitFailed);
        }
        Ok(true)
    }
}

pub(super) struct OutputSource {
    events: VecDeque<Result<ProcessOutputSourceEventV1, ProcessOutputSourceErrorV1>>,
    reads: Cell<u32>,
    budgets: Vec<ProcessOutputReadBudgetV1>,
}

impl OutputSource {
    pub(super) fn terminal() -> Self {
        Self::new([
            Ok(ProcessOutputSourceEventV1::End {
                sequence: 0,
                stream: super::ProcessOutputStreamV1::Stdout,
            }),
            Ok(ProcessOutputSourceEventV1::End {
                sequence: 1,
                stream: super::ProcessOutputStreamV1::Stderr,
            }),
        ])
    }

    pub(super) fn streamed() -> Self {
        Self::new([
            Ok(ProcessOutputSourceEventV1::Chunk {
                sequence: 0,
                stream: super::ProcessOutputStreamV1::Stdout,
                bytes: Box::from(*b"out"),
                source_has_more: false,
            }),
            Ok(ProcessOutputSourceEventV1::End {
                sequence: 1,
                stream: super::ProcessOutputStreamV1::Stdout,
            }),
            Ok(ProcessOutputSourceEventV1::Chunk {
                sequence: 2,
                stream: super::ProcessOutputStreamV1::Stderr,
                bytes: Box::from(*b"err"),
                source_has_more: false,
            }),
            Ok(ProcessOutputSourceEventV1::End {
                sequence: 3,
                stream: super::ProcessOutputStreamV1::Stderr,
            }),
        ])
    }

    pub(super) fn violating() -> Self {
        Self::new([Ok(ProcessOutputSourceEventV1::Chunk {
            sequence: 1,
            stream: super::ProcessOutputStreamV1::Stdout,
            bytes: Box::from(*b"partial"),
            source_has_more: false,
        })])
    }

    pub(super) fn new<const N: usize>(
        events: [Result<ProcessOutputSourceEventV1, ProcessOutputSourceErrorV1>; N],
    ) -> Self {
        Self {
            events: events.into(),
            reads: Cell::new(0),
            budgets: Vec::new(),
        }
    }

    pub(super) const fn reads(&self) -> u32 {
        self.reads.get()
    }

    pub(super) fn budgets(&self) -> &[ProcessOutputReadBudgetV1] {
        &self.budgets
    }
}

impl ProcessOutputSourcePortV1 for OutputSource {
    fn next_bounded(
        &mut self,
        budget: ProcessOutputReadBudgetV1,
    ) -> Result<ProcessOutputSourceEventV1, ProcessOutputSourceErrorV1> {
        self.reads.set(self.reads.get() + 1);
        self.budgets.push(budget);
        self.events
            .pop_front()
            .unwrap_or(Err(ProcessOutputSourceErrorV1::Closed))
    }

    fn stop_capture(
        &mut self,
        _: ProcessOutputStopReasonV1,
    ) -> Result<ProcessOutputStopEvidenceV1, ProcessOutputSourceErrorV1> {
        Ok(ProcessOutputStopEvidenceV1::new(false, false))
    }
}

pub(super) struct Clock<'a> {
    values: &'a [u64],
    index: Cell<usize>,
}

impl<'a> Clock<'a> {
    pub(super) fn new(values: &'a [u64]) -> Self {
        Self {
            values,
            index: Cell::new(0),
        }
    }
}

impl ProcessMonotonicClockV1 for Clock<'_> {
    fn now_ticks(&self) -> u64 {
        let index = self.index.get();
        self.index.set(index.saturating_add(1));
        self.values
            .get(index)
            .copied()
            .unwrap_or_else(|| *self.values.last().unwrap_or(&0))
    }
}

pub(super) struct Cancel(pub(super) bool);
impl ProcessCancellationTokenV1 for Cancel {
    fn is_cancelled(&self) -> bool {
        self.0
    }
}

pub(super) struct CancelSequence<'a> {
    values: &'a [bool],
    index: Cell<usize>,
}

impl<'a> CancelSequence<'a> {
    pub(super) fn new(values: &'a [bool]) -> Self {
        Self {
            values,
            index: Cell::new(0),
        }
    }
}

impl ProcessCancellationTokenV1 for CancelSequence<'_> {
    fn is_cancelled(&self) -> bool {
        let index = self.index.get();
        self.index.set(index.saturating_add(1));
        self.values.get(index).copied().unwrap_or(false)
    }
}

pub(super) fn admission() -> EffectAdmission {
    EffectAdmission {
        permit_id: "sealed-permit".to_owned(),
    }
}

pub(super) fn input(marker: u8) -> DispatchInputV1 {
    let binding = ProcessLifecycleBindingV1::new(
        ProcessOwnerIdV1::new([marker; 16]).unwrap(),
        ProcessAttemptIdV1::new([marker + 1; 16]).unwrap(),
        ProcessSessionIdV1::new([marker + 2; 16]).unwrap(),
        ProcessGenerationIdV1::new([marker + 3; 16]).unwrap(),
        HeldProcessTreeHandleV1::new([marker + 4; 16]).unwrap(),
    );
    let file = HeldFileIdentityV1::new([marker + 5; 16], [1; 32], [2; 32], [3; 32], 1).unwrap();
    let executable = VerifiedExecutableV1::new(
        file.clone(),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let cwd = VerifiedCwdV1::new(
        file,
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    DispatchInputV1 {
        digest: [marker + 6; 32],
        claim_binding: ProcessClaimBindingV1::from_lifecycle(&binding),
        request: ProcessPlatformRequestV1::new([marker + 6; 32], executable, cwd).unwrap(),
        binding,
        timeout_ticks: 1,
        cancellation_permitted: true,
        output_bounds: ProcessOutputBoundsV1::new(0, 4, 4, 8).unwrap(),
        output_caller: ProcessOutputCallerIdV1::new([marker + 7; 16]).unwrap(),
    }
}
