//! Same immutable original attempt/spent/binding/trust/once across conservative recovery.
use super::{
    attempt::{self, Attempt},
    bootstrap,
    context::CaseContext,
    metadata::Area,
    observations,
    records::Cut,
    recovery_receipts::{self, Receipts},
    workspace,
};
use crate::{
    ProjectTrustStore,
    store::{LocalCommandAttemptState, StoreTransaction},
};
use runne_domain::task_run::TaskRunState;

pub(super) fn before_settle(
    context: &CaseContext,
    area: &Area,
    cut: &Cut,
    store: &StoreTransaction,
    trust: &ProjectTrustStore,
    local: LocalCommandAttemptState,
    sql_state: &str,
) -> Attempt {
    assert_eq!(
        observations::stream(store, area, TaskRunState::Running),
        (cut.durable.stream_version, cut.durable.event_ids.clone())
    );
    observations::capture(store, area, local);
    let reader = observations::reader(context, area);
    let attempt = attempt::observe(&reader, area, sql_state);
    attempt.same_immutable(&cut.durable.attempt);
    assert_eq!(observations::spent(&reader, area), cut.durable.spent);
    observations::no_factual_terminal_or_provider(&reader, area);
    observations::count(&reader, "taskrun_terminal_settlement_receipts", area, 0);
    observations::count(&reader, "taskrun_local_command_stop_receipts", area, 0);
    bootstrap::trust(trust, area);
    workspace::pending(context, area);
    context.deadline.check();
    attempt
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Settled {
    pub attempt: Attempt,
    pub receipts: Receipts,
    pub stream: (u64, Vec<Vec<u8>>),
}

pub(super) fn settled(
    context: &CaseContext,
    area: &Area,
    cut: &Cut,
    store: &StoreTransaction,
    trust: &ProjectTrustStore,
    proof_epoch: u64,
    stream: &(u64, Vec<Vec<u8>>),
) -> Settled {
    assert_eq!(
        &observations::stream(store, area, TaskRunState::Unrecoverable),
        stream
    );
    observations::capture(store, area, LocalCommandAttemptState::OutcomeUnknown);
    let fresh = observations::reader(context, area);
    let attempt = attempt::observe(&fresh, area, "outcome_unknown");
    attempt.same_immutable(&cut.durable.attempt);
    let receipts = recovery_receipts::observe(
        &fresh,
        area,
        proof_epoch,
        stream.1.last().unwrap(),
        stream.0,
    );
    assert_eq!(observations::spent(&fresh, area), cut.durable.spent);
    bootstrap::trust(trust, area);
    workspace::pending(context, area);
    context.deadline.check();
    Settled {
        attempt,
        receipts,
        stream: stream.clone(),
    }
}
