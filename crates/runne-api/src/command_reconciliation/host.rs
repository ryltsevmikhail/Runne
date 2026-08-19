use super::{
    CommandReconciliationContext, CommandReconciliationDisposition, CommandReconciliationWitness,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandReconciliationHostError {
    Conflict,
    Backpressure,
    Unavailable,
    InvariantViolation,
}

impl CommandReconciliationHostError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Conflict => "command_conflict",
            Self::Backpressure => "runtime_backpressure",
            Self::Unavailable => "runtime_unavailable",
            Self::InvariantViolation => "runtime_invariant_violation",
        }
    }
}

pub trait CommandReconciliationHostPort: Send + Sync {
    fn reconcile_command(
        &self,
        context: CommandReconciliationContext,
        witness: CommandReconciliationWitness,
    ) -> impl std::future::Future<
        Output = Result<CommandReconciliationDisposition, CommandReconciliationHostError>,
    > + Send;
}
