use super::*;
use std::collections::VecDeque;

struct NativeSteps {
    responses: VecDeque<Result<Vec<[u8; 16]>, RecoveryRunError>>,
    effects: Vec<[u8; 16]>,
    fail_effect: bool,
}
impl CleanupSteps for NativeSteps {
    async fn discover(&mut self) -> Result<Vec<[u8; 16]>, RecoveryRunError> {
        self.responses.pop_front().expect("unexpected discovery")
    }
    async fn recover(&mut self, operation: [u8; 16]) -> Result<(), RecoveryRunError> {
        self.effects.push(operation);
        if self.fail_effect {
            Err(RecoveryRunError::Transport)
        } else {
            Ok(())
        }
    }
}

fn steps(responses: Vec<Result<Vec<[u8; 16]>, RecoveryRunError>>) -> NativeSteps {
    NativeSteps {
        responses: responses.into(),
        effects: vec![],
        fail_effect: false,
    }
}

#[tokio::test]
async fn empty_cleanup_queue_never_renews_or_runs_writer() {
    let mut native = steps(vec![Ok(vec![])]);
    assert_eq!(drain(&mut native).await, Ok(()));
    assert!(native.effects.is_empty());
}

#[tokio::test]
async fn scheduler_rediscovers_after_each_effect_instead_of_using_stale_batch() {
    let mut native = steps(vec![
        Ok(vec![[1; 16], [2; 16]]),
        Ok(vec![[3; 16]]),
        Ok(vec![]),
    ]);
    assert_eq!(drain(&mut native).await, Ok(()));
    assert_eq!(native.effects, vec![[1; 16], [3; 16]]);
    assert!(native.responses.is_empty());
}

#[tokio::test]
async fn scheduler_never_retries_failed_or_still_visible_effect() {
    let mut native = steps(vec![Ok(vec![[1; 16]]), Ok(vec![[1; 16]])]);
    assert_eq!(
        drain(&mut native).await,
        Err(RecoveryRunError::NonCompleted)
    );
    assert_eq!(native.effects, vec![[1; 16]]);
    let mut native = steps(vec![Ok(vec![[1; 16]])]);
    native.fail_effect = true;
    assert_eq!(drain(&mut native).await, Err(RecoveryRunError::Transport));
    assert_eq!(native.effects, vec![[1; 16]]);
}

#[tokio::test]
async fn scheduler_fails_closed_on_discovery_error_or_invalid_id() {
    for response in [Err(RecoveryRunError::Transport), Ok(vec![[0; 16]])] {
        let mut native = steps(vec![response]);
        assert!(drain(&mut native).await.is_err());
        assert!(native.effects.is_empty());
    }
}

#[tokio::test]
async fn scheduler_bounds_effects_without_reporting_unfinished_queue_as_success() {
    let mut native = steps((1..=65).map(|n| Ok(vec![[n; 16]])).collect());
    assert_eq!(
        drain(&mut native).await,
        Err(RecoveryRunError::NonCompleted)
    );
    assert_eq!(native.effects.len(), 64);
    assert_eq!(native.effects.last(), Some(&[64; 16]));
}
