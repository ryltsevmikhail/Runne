//! Application mapping for authoritative command reconciliation.

use runne_api::{
    AuthoritativeCommandOutcome, CommandReconciliationContext, CommandReconciliationDisposition,
    CommandReconciliationWitness,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandReconciliationRepositoryError {
    Conflict,
    Unavailable,
    InvariantViolation,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandReconciliationEvidence {
    NotCommitted,
    TextGenerationStarted,
    Terminal(Box<AuthoritativeCommandOutcome>),
}
pub trait CommandReconciliationRepository: Clone + Send + Sync + 'static {
    fn reconcile_command(
        &self,
        context: &CommandReconciliationContext,
        witness: &CommandReconciliationWitness,
    ) -> Result<CommandReconciliationEvidence, CommandReconciliationRepositoryError>;
}
#[derive(Clone)]
pub struct CommandReconciliationService<R> {
    repository: R,
}
impl<R: CommandReconciliationRepository> CommandReconciliationService<R> {
    #[must_use]
    pub fn new(repository: R) -> Self {
        Self { repository }
    }
    pub fn reconcile_command(
        &self,
        context: &CommandReconciliationContext,
        witness: &CommandReconciliationWitness,
    ) -> Result<CommandReconciliationDisposition, CommandReconciliationRepositoryError> {
        match self.repository.reconcile_command(context, witness)? {
            CommandReconciliationEvidence::NotCommitted => {
                Ok(CommandReconciliationDisposition::not_committed_retryable())
            }
            CommandReconciliationEvidence::TextGenerationStarted => {
                Ok(CommandReconciliationDisposition::indeterminate())
            }
            CommandReconciliationEvidence::Terminal(outcome) => {
                CommandReconciliationDisposition::durably_recorded(witness, *outcome)
                    .map_err(|_| CommandReconciliationRepositoryError::InvariantViolation)
            }
        }
    }
}
