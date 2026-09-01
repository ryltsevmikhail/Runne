use std::future::Future;

pub(super) trait PostFenceEnrollmentDependencies {
    type Output;
    type Error;

    fn require_rotated_session(&mut self) -> Result<(), Self::Error>;
    fn revalidate_updater(&mut self) -> Result<(), Self::Error>;
    fn admit_registry(self) -> Result<Self::Output, Self::Error>;
}

pub(super) async fn run_post_fence_branches<D, X, F>(
    mut dependencies: D,
    cleanup: X,
) -> Result<D::Output, D::Error>
where
    D: PostFenceEnrollmentDependencies,
    X: FnOnce() -> F,
    F: Future<Output = ()>,
{
    let result = dependencies
        .require_rotated_session()
        .and_then(|()| dependencies.revalidate_updater())
        .and_then(|()| dependencies.admit_registry());
    if result.is_err() {
        cleanup().await;
    }
    result
}

pub(super) fn spawn_cleanup_supervised_transcript<W, X, F>(
    work: W,
    cleanup: X,
) -> (
    tokio::sync::oneshot::Receiver<Result<(), ()>>,
    tokio::sync::oneshot::Receiver<()>,
)
where
    W: FnOnce() -> Result<(), ()> + Send + 'static,
    X: FnOnce() -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let (result_sender, result) = tokio::sync::oneshot::channel();
    let (completion_sender, completion) = tokio::sync::oneshot::channel();
    tauri::async_runtime::spawn(async move {
        let outcome = tauri::async_runtime::spawn_blocking(work)
            .await
            .map_err(|_| ())
            .and_then(core::convert::identity);
        if outcome.is_err() {
            cleanup().await;
        }
        let _ = result_sender.send(outcome);
        let _ = completion_sender.send(());
    });
    (result, completion)
}
