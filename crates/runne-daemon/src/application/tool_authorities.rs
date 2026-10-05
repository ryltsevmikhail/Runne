use runne_application::ports::{
    ReconciliationError, ReconciliationQueryPort, RetryScheduleError, RetrySchedulePort, TimeError,
    TimePort, WakeEvidenceError, WakeEvidenceQueryPort,
};
use runne_domain::agent_loop::{StepOutcomeRef, WakeCondition, WakeEvidenceRef};
use runne_domain::id::{AttemptId, IntegrityDigest, TaskRunId};
use runne_domain::recovery::ReconciliationResultRef;
use runne_domain::reference::BudgetReservationRef;
use runne_store::store::StoreTransaction;

/// Restrictive production authorities for the internal D2 loop service.
/// Unsupported retry, wake, and reconciliation operations fail closed.
#[derive(Clone)]
pub(super) struct D2ToolLoopAuthority {
    store: StoreTransaction,
    provider: Option<std::sync::Arc<crate::canonical_provider::DaemonCanonicalProviderService>>,
    root_admission: crate::application::root_handle_admission::RootAdmissionGateway,
}

impl D2ToolLoopAuthority {
    pub(super) fn new(
        store: StoreTransaction,
        provider: Option<std::sync::Arc<crate::canonical_provider::DaemonCanonicalProviderService>>,
        root_admission: crate::application::root_handle_admission::RootAdmissionGateway,
    ) -> Self {
        Self {
            store,
            provider,
            root_admission,
        }
    }
}

impl TimePort for D2ToolLoopAuthority {
    fn now_unix_us(&self) -> Result<i64, TimeError> {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TimeError::OutOfRange)?;
        i64::try_from(elapsed.as_micros()).map_err(|_| TimeError::OutOfRange)
    }
}

impl RetrySchedulePort for D2ToolLoopAuthority {
    fn prepare(
        &self,
        _: TaskRunId,
        _: AttemptId,
        _: u64,
        _: &StepOutcomeRef,
        _: &IntegrityDigest,
        _: &BudgetReservationRef,
        _: i64,
    ) -> Result<runne_application::ports::PreparedRetrySchedule, RetryScheduleError> {
        Err(RetryScheduleError::Unavailable)
    }
}

impl WakeEvidenceQueryPort for D2ToolLoopAuthority {
    fn validate_current(
        &self,
        _: &WakeEvidenceRef,
        _: TaskRunId,
        _: runne_domain::id::CycleId,
        _: &WakeCondition,
    ) -> Result<(), WakeEvidenceError> {
        Err(WakeEvidenceError::Unavailable)
    }
}

impl ReconciliationQueryPort for D2ToolLoopAuthority {
    fn validate_current(
        &self,
        _: &ReconciliationResultRef,
        _: TaskRunId,
        _: AttemptId,
        _: u64,
        _: u64,
    ) -> Result<(), ReconciliationError> {
        Err(ReconciliationError::Unavailable)
    }
}

#[path = "tool_authorities/verification.rs"]
mod verification;

pub(crate) fn derive_expected_evaluation(
    store: StoreTransaction,
    provider: Option<std::sync::Arc<crate::canonical_provider::DaemonCanonicalProviderService>>,
    root_admission: crate::application::root_handle_admission::RootAdmissionGateway,
    taskrun_id: TaskRunId,
) -> Result<
    runne_application::ports::PlanEvaluation,
    runne_application::ports::VerificationQueryError,
> {
    D2ToolLoopAuthority::new(store, provider, root_admission).derive_expected_evaluation(taskrun_id)
}

pub(crate) fn verify_historical_completed(
    store: StoreTransaction,
    provider: Option<std::sync::Arc<crate::canonical_provider::DaemonCanonicalProviderService>>,
    root_admission: crate::application::root_handle_admission::RootAdmissionGateway,
    taskrun_id: TaskRunId,
) -> Result<
    runne_application::ports::PlanEvaluation,
    runne_application::ports::VerificationQueryError,
> {
    D2ToolLoopAuthority::new(store, provider, root_admission)
        .verify_historical_completed(taskrun_id)
}
