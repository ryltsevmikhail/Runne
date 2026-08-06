#![allow(dead_code)]

use core::fmt;

use super::{
    approvals::PossibleDispatchBoundaryWitness,
    authority::{ApprovalSet, ConsumedAttempt},
    report::LifecycleDisposition,
};

/// A check performed immediately before the named boundary.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Checkpoint {
    CredentialMaterialization,
    NetworkAuthorityClaim,
    BudgetReservationClaim,
    PossibleDispatchBoundary,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Observation {
    Cancelled,
    TimedOut,
    Disconnected,
    TlsAmbiguity,
    HttpAmbiguity,
    MalformedSse,
    MissingTerminalUsage,
    MissingTerminalResponse,
    TransportError,
}

macro_rules! closed { ($($type:ty => $name:literal),+ $(,)?) => { $(
    impl fmt::Debug for $type {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str($name) }
    }
    impl fmt::Display for $type {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str($name) }
    }
)+ }; }
closed!(Checkpoint => "Checkpoint", Observation => "Observation");

pub(super) struct ObservationReport {
    pub(super) approvals_consumed: bool,
    pub(super) attempt_consumed: bool,
}
impl ObservationReport {
    pub(super) const fn disposition(&self) -> LifecycleDisposition {
        LifecycleDisposition::Uncertain
    }
    pub(super) const fn approvals_consumed(&self) -> bool {
        self.approvals_consumed
    }
    pub(super) const fn attempt_consumed(&self) -> bool {
        self.attempt_consumed
    }
    pub(super) const fn retry(&self) -> bool {
        false
    }
    pub(super) const fn redispatch(&self) -> bool {
        false
    }
    pub(super) const fn second_reservation(&self) -> bool {
        false
    }
    pub(super) const fn settlement(&self) -> bool {
        false
    }
    pub(super) const fn manual_reconciliation(&self) -> bool {
        true
    }
    pub(super) const fn reservation_held(&self) -> bool {
        true
    }
}
closed!(ObservationReport => "ObservationReport");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OfflineCanaryFence {
    Disarmed,
    Armed,
    CredentialAuthorized,
    NetworkAuthorized,
    BudgetReserved,
    Dispatching,
    Terminal,
    Uncertain,
    Aborted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EffectDisposition {
    DefinitelyNotDispatched,
    Dispatching,
    Terminal,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FenceError {
    InvalidTransition,
}
enum ObservationState {
    Terminal,
    Uncertain,
}

pub(super) struct Fence {
    state: OfflineCanaryFence,
    approvals: Option<ApprovalSet>,
    reserved: bool,
    attempt: Option<ConsumedAttempt>,
}
impl Default for Fence {
    fn default() -> Self {
        Self {
            state: OfflineCanaryFence::Disarmed,
            approvals: None,
            reserved: false,
            attempt: None,
        }
    }
}
impl fmt::Debug for Fence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Fence")
    }
}
impl Fence {
    pub(super) fn armed(approvals: ApprovalSet) -> Self {
        Self {
            state: OfflineCanaryFence::Armed,
            approvals: Some(approvals),
            reserved: false,
            attempt: None,
        }
    }
    pub(super) const fn state(&self) -> OfflineCanaryFence {
        self.state
    }
    pub(super) fn credential_authorized(mut self) -> Result<Self, FenceError> {
        if self.state != OfflineCanaryFence::Armed || self.approvals.is_none() {
            return Err(FenceError::InvalidTransition);
        }
        self.state = OfflineCanaryFence::CredentialAuthorized;
        Ok(self)
    }
    pub(super) fn network_authorized(mut self) -> Result<Self, FenceError> {
        if self.state != OfflineCanaryFence::CredentialAuthorized || self.approvals.is_none() {
            return Err(FenceError::InvalidTransition);
        }
        self.state = OfflineCanaryFence::NetworkAuthorized;
        Ok(self)
    }
    pub(super) fn reserve_budget(mut self) -> Result<Self, FenceError> {
        if self.state != OfflineCanaryFence::NetworkAuthorized || self.approvals.is_none() {
            return Err(FenceError::InvalidTransition);
        }
        self.state = OfflineCanaryFence::BudgetReserved;
        self.reserved = true;
        Ok(self)
    }
    pub(super) fn enter_dispatching(
        mut self,
        witness: PossibleDispatchBoundaryWitness,
    ) -> Result<Self, FenceError> {
        // 4-я точка проверки: граница возможного dispatch.
        let _ = Checkpoint::PossibleDispatchBoundary;
        if self.state != OfflineCanaryFence::BudgetReserved || !self.reserved {
            return Err(FenceError::InvalidTransition);
        }
        let approvals = self
            .approvals
            .as_ref()
            .ok_or(FenceError::InvalidTransition)?;
        if !witness.matches(approvals.replay()) {
            return Err(FenceError::InvalidTransition);
        }
        self.attempt = Some(
            self.approvals
                .take()
                .expect("approvals presence checked above")
                .consume(),
        );
        self.state = OfflineCanaryFence::Dispatching;
        Ok(self)
    }
    pub(super) fn consume_terminal_observation(&mut self) -> Result<ConsumedAttempt, FenceError> {
        self.consume_observation_as_terminal()
    }
    pub(super) fn consume_uncertain_observation(&mut self) -> Result<ConsumedAttempt, FenceError> {
        self.consume_observation_as_uncertain()
    }
    fn consume_observation_as_terminal(&mut self) -> Result<ConsumedAttempt, FenceError> {
        self.take_observation_basis(ObservationState::Terminal)
    }
    fn consume_observation_as_uncertain(&mut self) -> Result<ConsumedAttempt, FenceError> {
        self.take_observation_basis(ObservationState::Uncertain)
    }
    fn take_observation_basis(
        &mut self,
        state: ObservationState,
    ) -> Result<ConsumedAttempt, FenceError> {
        if self.state != OfflineCanaryFence::Dispatching || !self.reserved {
            return Err(FenceError::InvalidTransition);
        }
        let attempt = self.attempt.take().ok_or(FenceError::InvalidTransition)?;
        self.reserved = false;
        self.state = match state {
            ObservationState::Terminal => OfflineCanaryFence::Terminal,
            ObservationState::Uncertain => OfflineCanaryFence::Uncertain,
        };
        Ok(attempt)
    }
    pub(super) fn abort(mut self) -> Result<AbortOutcome, FenceError> {
        if !matches!(
            self.state,
            OfflineCanaryFence::Disarmed
                | OfflineCanaryFence::Armed
                | OfflineCanaryFence::CredentialAuthorized
                | OfflineCanaryFence::NetworkAuthorized
                | OfflineCanaryFence::BudgetReserved
        ) {
            return Err(FenceError::InvalidTransition);
        }
        let released = self.reserved;
        self.reserved = false;
        self.state = OfflineCanaryFence::Aborted;
        Ok(AbortOutcome {
            fence: self.state,
            released,
            approvals: self.approvals.take(),
        })
    }
}
pub(super) struct AbortOutcome {
    fence: OfflineCanaryFence,
    released: bool,
    approvals: Option<ApprovalSet>,
}
impl AbortOutcome {
    pub(super) const fn fence(&self) -> OfflineCanaryFence {
        self.fence
    }
    pub(super) const fn disposition(&self) -> EffectDisposition {
        EffectDisposition::DefinitelyNotDispatched
    }
    pub(super) const fn reservation_released(&self) -> bool {
        self.released
    }
    pub(super) const fn approvals_unconsumed(&self) -> bool {
        self.approvals.is_some()
    }
    pub(super) fn into_approvals(mut self) -> Option<ApprovalSet> {
        self.approvals.take()
    }
}
impl fmt::Debug for AbortOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AbortOutcome")
    }
}
