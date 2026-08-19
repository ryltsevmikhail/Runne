use std::sync::{Arc, Mutex};

#[cfg(test)]
use std::cell::Cell;

use crate::fixture::{FixtureCallResult, FixtureMcpFailure};

use super::super::super::process_call::ProcessEffectKey;
use super::super::{
    FixtureState,
    process_audit::{FixtureAuditProcessPhase, FixtureAuditRecord},
};
use super::{
    ProcessLedgerState, ProcessReceiptIdentity, ProcessRefundReason, ProcessReservationReceipt,
};

pub(in crate::fixture) enum ProcessReserveOutcome {
    Owner(ProcessReservationReceipt),
    BusyReserved,
    TerminalReplay(FixtureCallResult),
    InvocationConflict,
}
pub(in crate::fixture) use super::types::ProcessLedgerEntry;

#[cfg(test)]
thread_local! {
    static TERMINAL_REPLAY_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(in crate::fixture) fn terminal_replay_count_for_test() -> usize {
    TERMINAL_REPLAY_COUNT.with(Cell::get)
}

#[cfg(test)]
fn record_terminal_replay() {
    TERMINAL_REPLAY_COUNT.with(|count| count.set(count.get() + 1));
}

pub(in crate::fixture) fn reserve_process(
    state: &Arc<Mutex<FixtureState>>,
    key: ProcessEffectKey,
) -> Result<ProcessReserveOutcome, FixtureMcpFailure> {
    let mut state = state
        .lock()
        .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
    let invocation = key.invocation_id().to_owned();
    if let Some(entry) = state.process_ledger.get(&invocation) {
        if entry.key != key {
            return Ok(ProcessReserveOutcome::InvocationConflict);
        }
        match &entry.state {
            ProcessLedgerState::Completed { audit, .. } => {
                #[cfg(test)]
                record_terminal_replay();
                return Ok(ProcessReserveOutcome::TerminalReplay(
                    audit.result().expect("completed result"),
                ));
            }
            ProcessLedgerState::Uncertain(_) => {
                #[cfg(test)]
                record_terminal_replay();
                return Ok(ProcessReserveOutcome::TerminalReplay(
                    FixtureCallResult::Uncertain,
                ));
            }
            ProcessLedgerState::Reserved | ProcessLedgerState::Admitted => {
                return Ok(ProcessReserveOutcome::BusyReserved);
            }
            ProcessLedgerState::Refunded => {
                let next = entry
                    .current_attempt
                    .checked_add(1)
                    .ok_or(FixtureMcpFailure::AccountingMismatch)?;
                let remaining = state
                    .remaining
                    .checked_sub(1)
                    .ok_or(FixtureMcpFailure::AccountingDenied)?;
                let receipt = ProcessReservationReceipt::new(identity(&key, next));
                let audit = FixtureAuditRecord::process(
                    &key,
                    FixtureAuditProcessPhase::Reserved,
                    None,
                    None,
                    None,
                );
                let entry = state
                    .process_ledger
                    .get_mut(&invocation)
                    .expect("checked entry");
                entry.current_attempt = next;
                entry.state = ProcessLedgerState::Reserved;
                state.remaining = remaining;
                state.audit.push(audit);
                return Ok(ProcessReserveOutcome::Owner(receipt));
            }
        }
    }
    let remaining = state
        .remaining
        .checked_sub(1)
        .ok_or(FixtureMcpFailure::AccountingDenied)?;
    let receipt = ProcessReservationReceipt::new(identity(&key, 1));
    let audit =
        FixtureAuditRecord::process(&key, FixtureAuditProcessPhase::Reserved, None, None, None);
    state.process_ledger.insert(
        invocation,
        ProcessLedgerEntry {
            key,
            current_attempt: 1,
            refunded_through: 0,
            state: ProcessLedgerState::Reserved,
        },
    );
    state.remaining = remaining;
    state.audit.push(audit);
    Ok(ProcessReserveOutcome::Owner(receipt))
}

pub(in crate::fixture) fn refund_process(
    state: &Arc<Mutex<FixtureState>>,
    receipt: ProcessReservationReceipt,
    reason: ProcessRefundReason,
) -> Result<(), FixtureMcpFailure> {
    let mut state = state
        .lock()
        .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
    let entry = state
        .process_ledger
        .get(&receipt.identity.invocation_id)
        .ok_or(FixtureMcpFailure::InvalidStateTransition)?;
    if !receipt_matches(entry, &receipt.identity)
        || !matches!(entry.state, ProcessLedgerState::Reserved)
    {
        return Err(FixtureMcpFailure::InvalidStateTransition);
    }
    let remaining = state
        .remaining
        .checked_add(1)
        .ok_or(FixtureMcpFailure::AccountingMismatch)?;
    let key = entry.key.clone();
    let entry = state
        .process_ledger
        .get_mut(&receipt.identity.invocation_id)
        .expect("checked entry");
    entry.refunded_through = entry.current_attempt;
    entry.state = ProcessLedgerState::Refunded;
    let audit = FixtureAuditRecord::process(
        &key,
        FixtureAuditProcessPhase::Refunded,
        Some(FixtureAuditRecord::refund_reason(reason)),
        None,
        None,
    );
    state.remaining = remaining;
    state.audit.push(audit);
    Ok(())
}

#[cfg(test)]
impl super::super::FixtureMcpRuntime {
    pub(in crate::fixture) fn reserve_process(
        &self,
        key: ProcessEffectKey,
    ) -> Result<ProcessReserveOutcome, FixtureMcpFailure> {
        reserve_process(&self.state, key)
    }

    pub(in crate::fixture) fn refund_process(
        &self,
        receipt: ProcessReservationReceipt,
        reason: ProcessRefundReason,
    ) -> Result<(), FixtureMcpFailure> {
        refund_process(&self.state, receipt, reason)
    }

    #[cfg(test)]
    pub(in crate::fixture) fn receipt_for_test(
        &self,
        identity: ProcessReceiptIdentity,
    ) -> ProcessReservationReceipt {
        ProcessReservationReceipt::new(identity)
    }
    #[cfg(test)]
    pub(in crate::fixture) fn duplicate_receipt_for_test(
        &self,
        receipt: &ProcessReservationReceipt,
    ) -> ProcessReservationReceipt {
        receipt.duplicate_for_test()
    }
    #[cfg(test)]
    pub(in crate::fixture) fn set_attempt_for_test(&self, invocation: &str, attempt: u64) {
        self.state
            .lock()
            .unwrap()
            .process_ledger
            .get_mut(invocation)
            .unwrap()
            .current_attempt = attempt;
    }
}

pub(super) fn identity(key: &ProcessEffectKey, attempt: u64) -> ProcessReceiptIdentity {
    ProcessReceiptIdentity {
        invocation_id: key.invocation_id().to_owned(),
        key_digest: key.digest(),
        attempt,
    }
}
pub(super) fn receipt_matches(
    entry: &ProcessLedgerEntry,
    identity: &ProcessReceiptIdentity,
) -> bool {
    identity.key_digest == entry.key.digest()
        && identity.attempt == entry.current_attempt
        && identity.attempt > entry.refunded_through
}
