use super::{
    AuthoritativeCommandOutcome, CommandReconciliationHostError, CommandReconciliationWitness,
};

/// Closed, validated result of observing one authoritative command identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReconciliationDisposition {
    inner: Disposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Disposition {
    DurablyRecorded(Box<AuthoritativeCommandOutcome>),
    NotCommittedRetryable,
    Indeterminate,
}

impl CommandReconciliationDisposition {
    pub fn durably_recorded(
        witness: &CommandReconciliationWitness,
        outcome: AuthoritativeCommandOutcome,
    ) -> Result<Self, CommandReconciliationHostError> {
        (witness.operation() == outcome.operation())
            .then_some(Self {
                inner: Disposition::DurablyRecorded(Box::new(outcome)),
            })
            .ok_or(CommandReconciliationHostError::InvariantViolation)
    }

    #[must_use]
    pub const fn not_committed_retryable() -> Self {
        Self {
            inner: Disposition::NotCommittedRetryable,
        }
    }

    #[must_use]
    pub const fn indeterminate() -> Self {
        Self {
            inner: Disposition::Indeterminate,
        }
    }

    #[must_use]
    pub fn outcome(&self) -> Option<&AuthoritativeCommandOutcome> {
        match &self.inner {
            Disposition::DurablyRecorded(outcome) => Some(outcome),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_not_committed_retryable(&self) -> bool {
        matches!(self.inner, Disposition::NotCommittedRetryable)
    }

    #[must_use]
    pub const fn is_indeterminate(&self) -> bool {
        matches!(self.inner, Disposition::Indeterminate)
    }
}
