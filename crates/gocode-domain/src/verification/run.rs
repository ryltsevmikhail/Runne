use crate::verification::digest::VerificationDigest;
use crate::verification::identity::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunState {
    Pending,
    Running,
    Evaluating,
    AwaitingReview,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunResult {
    Passed,
    Failed,
    Blocked,
    RequiresReview,
}

#[derive(Clone, Debug)]
pub struct VerificationRun {
    pub run_id: RunID,
    pub plan_id: PlanID,
    pub plan_revision: u64,
    pub profile_id: ProfileID,
    pub profile_digest: VerificationDigest,
    pub state: RunState,
    pub result: Option<RunResult>,
}

impl VerificationRun {
    pub fn new(
        run_id: RunID,
        plan_id: PlanID,
        plan_revision: u64,
        profile_id: ProfileID,
        profile_digest: VerificationDigest,
    ) -> Self {
        Self {
            run_id,
            plan_id,
            plan_revision,
            profile_id,
            profile_digest,
            state: RunState::Pending,
            result: None,
        }
    }

    pub fn start(&mut self) -> Result<(), RunError> {
        if self.state != RunState::Pending {
            return Err(RunError::InvalidTransition);
        }
        self.state = RunState::Running;
        Ok(())
    }

    pub fn complete(&mut self, result: RunResult) -> Result<(), RunError> {
        if self.state != RunState::Evaluating && self.state != RunState::AwaitingReview {
            return Err(RunError::InvalidTransition);
        }
        if result == RunResult::Blocked {
            return Err(RunError::BlockedNotTerminal);
        }
        self.state = RunState::Completed;
        self.result = Some(result);
        Ok(())
    }

    pub fn awaiting_review(&mut self) -> Result<(), RunError> {
        if self.state != RunState::Evaluating {
            return Err(RunError::InvalidTransition);
        }
        self.state = RunState::AwaitingReview;
        self.result = Some(RunResult::RequiresReview);
        Ok(())
    }

    pub fn evaluate(&mut self) -> Result<(), RunError> {
        if self.state != RunState::Running {
            return Err(RunError::InvalidTransition);
        }
        self.state = RunState::Evaluating;
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), RunError> {
        if matches!(
            self.state,
            RunState::Completed | RunState::Failed | RunState::Cancelled
        ) {
            return Err(RunError::InvalidTransition);
        }
        self.state = RunState::Cancelled;
        Ok(())
    }
}

#[derive(Debug)]
pub enum RunError {
    InvalidTransition,
    BlockedNotTerminal,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::digest::VerificationDigest;
    use uuid::Uuid;

    fn test_run() -> VerificationRun {
        VerificationRun::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            1,
            Uuid::now_v7(),
            VerificationDigest::from_bytes([0u8; 32]),
        )
    }

    #[test]
    fn run_pending_to_running() {
        let mut r = test_run();
        r.start().unwrap();
        assert_eq!(r.state, RunState::Running);
    }
    #[test]
    fn run_running_to_evaluating() {
        let mut r = test_run();
        r.start().unwrap();
        r.evaluate().unwrap();
        assert_eq!(r.state, RunState::Evaluating);
    }
    #[test]
    fn run_evaluating_to_awaiting_review() {
        let mut r = test_run();
        r.start().unwrap();
        r.evaluate().unwrap();
        r.awaiting_review().unwrap();
        assert_eq!(r.state, RunState::AwaitingReview);
    }
    #[test]
    fn run_completed_passed() {
        let mut r = test_run();
        r.start().unwrap();
        r.evaluate().unwrap();
        r.complete(RunResult::Passed).unwrap();
        assert_eq!(r.state, RunState::Completed);
    }
    #[test]
    fn run_blocked_not_terminal() {
        let mut r = test_run();
        r.start().unwrap();
        r.evaluate().unwrap();
        assert!(r.complete(RunResult::Blocked).is_err());
    }
    #[test]
    fn run_cancel_from_pending() {
        let mut r = test_run();
        r.cancel().unwrap();
        assert_eq!(r.state, RunState::Cancelled);
    }
    #[test]
    fn run_cancel_from_running() {
        let mut r = test_run();
        r.start().unwrap();
        r.cancel().unwrap();
        assert_eq!(r.state, RunState::Cancelled);
    }
    #[test]
    fn run_cancel_completed_rejected() {
        let mut r = test_run();
        r.start().unwrap();
        r.evaluate().unwrap();
        r.complete(RunResult::Passed).unwrap();
        assert!(r.cancel().is_err());
    }
    #[test]
    fn run_start_already_running_rejected() {
        let mut r = test_run();
        r.start().unwrap();
        assert!(r.start().is_err());
    }
}
