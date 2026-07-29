use std::sync::{Arc, Mutex};
use std::time::Duration;

use gocode_opencode_compat::{
    CanonicalPrompt, CanonicalPromptResult, CanonicalSessionStatus, SessionV1HostError,
    SessionV1HostPort,
};
use gocode_runtime::opencode_session::{
    PromptExecutionFuture, PromptExecutionPort, RuntimeSessionV1Host,
};
use tokio::sync::Notify;

#[derive(Clone, Default)]
struct ControlledExecutor {
    started: Arc<Notify>,
    release: Arc<Notify>,
    cancelled: Arc<Mutex<bool>>,
}

impl PromptExecutionPort for ControlledExecutor {
    fn execute(
        &self,
        prompt: CanonicalPrompt,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> PromptExecutionFuture<'_> {
        Box::pin(async move {
            self.started.notify_one();
            tokio::select! {
                _ = self.release.notified() => Ok(CanonicalPromptResult {
                    session_id: prompt.session_id,
                    response: serde_json::json!({"done": true}),
                }),
                _ = cancellation.cancelled() => {
                    *self.cancelled.lock().unwrap() = true;
                    Err(SessionV1HostError::Conflict)
                }
            }
        })
    }
}

fn prompt() -> CanonicalPrompt {
    CanonicalPrompt {
        session_id: "ses_runtime_1".into(),
        message_id: Some("msg_runtime_1".into()),
        text_parts: vec!["hello".into()],
    }
}

#[tokio::test]
async fn async_prompt_owns_busy_status_until_execution_finishes() {
    let executor = ControlledExecutor::default();
    let host = RuntimeSessionV1Host::new(executor.clone());

    host.prompt_async(prompt()).await.unwrap();
    executor.started.notified().await;
    assert_eq!(
        host.status().await.unwrap(),
        vec![("ses_runtime_1".into(), CanonicalSessionStatus::Busy)]
    );
    assert_eq!(
        host.prompt_async(prompt()).await.unwrap_err(),
        SessionV1HostError::Conflict
    );

    executor.release.notify_waiters();
    tokio::task::yield_now().await;
    while !host.status().await.unwrap().is_empty() {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn abort_only_reports_true_for_an_owned_active_execution() {
    let executor = ControlledExecutor::default();
    let host = RuntimeSessionV1Host::new(executor.clone());
    assert!(!host.abort("ses_runtime_1".into()).await.unwrap());

    host.prompt_async(prompt()).await.unwrap();
    executor.started.notified().await;
    assert!(host.abort("ses_runtime_1".into()).await.unwrap());
    assert!(!host.abort("ses_runtime_1".into()).await.unwrap());

    while !*executor.cancelled.lock().unwrap() {
        tokio::task::yield_now().await;
    }
    while !host.status().await.unwrap().is_empty() {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn synchronous_prompt_returns_executor_result_and_releases_ownership() {
    let executor = ControlledExecutor::default();
    let host = RuntimeSessionV1Host::new(executor.clone());
    let release = executor.release.clone();
    tokio::spawn(async move {
        tokio::task::yield_now().await;
        release.notify_waiters();
    });
    let result = host.prompt(prompt()).await.unwrap();
    assert_eq!(result.response, serde_json::json!({"done": true}));
    assert!(host.status().await.unwrap().is_empty());
}

#[derive(Clone)]
struct IgnoringExecutor;

impl PromptExecutionPort for IgnoringExecutor {
    fn execute(
        &self,
        _: CanonicalPrompt,
        _: tokio_util::sync::CancellationToken,
    ) -> PromptExecutionFuture<'_> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn abort_times_out_if_downstream_never_acknowledges_cancellation() {
    let host = RuntimeSessionV1Host::new(IgnoringExecutor)
        .with_abort_timeout(Duration::from_millis(1))
        .unwrap();
    host.prompt_async(prompt()).await.unwrap();
    assert_eq!(
        host.abort("ses_runtime_1".into()).await.unwrap_err(),
        SessionV1HostError::Timeout
    );
}
