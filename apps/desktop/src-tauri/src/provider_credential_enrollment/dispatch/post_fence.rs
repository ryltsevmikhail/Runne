use std::future::Future;

pub(super) trait PostFenceEnrollmentDependencies {
    type Output;
    type Error;

    fn require_rotated_session(&mut self) -> Result<(), Self::Error>;
    fn revalidate_updater(&mut self) -> Result<(), Self::Error>;
    fn admit_registry(self) -> Result<Self::Output, Self::Error>;
}

pub(super) fn run_post_fence_branches<D>(mut dependencies: D) -> Result<D::Output, D::Error>
where
    D: PostFenceEnrollmentDependencies,
{
    dependencies
        .require_rotated_session()
        .and_then(|()| dependencies.revalidate_updater())
        .and_then(|()| dependencies.admit_registry())
}

pub(super) fn spawn_pre_fence_enrollment_owner<W, O, X, F, T, E>(
    work: W,
    cleanup: X,
) -> (
    tokio::sync::oneshot::Receiver<Result<T, E>>,
    tokio::sync::oneshot::Receiver<()>,
)
where
    W: FnOnce() -> O + Send + 'static,
    O: Future<Output = Result<T, E>> + Send + 'static,
    X: FnOnce() -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let (result_sender, result) = tokio::sync::oneshot::channel();
    let (completion_sender, completion) = tokio::sync::oneshot::channel();
    tauri::async_runtime::spawn(async move {
        let outcome = work().await;
        if outcome.is_err() {
            cleanup().await;
        }
        let _ = result_sender.send(outcome);
        let _ = completion_sender.send(());
    });
    (result, completion)
}
