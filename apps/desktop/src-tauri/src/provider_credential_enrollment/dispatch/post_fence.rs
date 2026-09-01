use std::future::Future;

pub(super) trait PostFenceEnrollmentDependencies {
    type Output;
    type Error;

    fn require_rotated_session(&mut self) -> Result<(), Self::Error>;
    fn revalidate_updater(&mut self) -> Result<(), Self::Error>;
    fn admit_registry(self) -> Result<Self::Output, Self::Error>;
}

pub(super) struct EnrollmentWatcher(tauri::async_runtime::JoinHandle<()>);

impl EnrollmentWatcher {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "command drop detaches the deliberately non-cancellable watcher"
        )
    )]
    pub(super) async fn wait(self) -> Result<(), tauri::Error> {
        self.0.await
    }
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

pub(super) fn spawn_pre_fence_enrollment_owner<W, O, X, F, J, T, E>(
    work: W,
    cleanup: X,
    join_failure: J,
) -> (
    tokio::sync::oneshot::Receiver<Result<T, E>>,
    EnrollmentWatcher,
)
where
    W: FnOnce() -> O + Send + 'static,
    O: Future<Output = Result<T, E>> + Send + 'static,
    X: FnOnce() -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
    J: FnOnce() -> E + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let (result_sender, result) = tokio::sync::oneshot::channel();
    let work = tauri::async_runtime::spawn(async move { work().await });
    let watcher = tauri::async_runtime::spawn(async move {
        let outcome = work.await.unwrap_or_else(|_| Err(join_failure()));
        if outcome.is_err() {
            let cleanup = tauri::async_runtime::spawn(async move { cleanup().await });
            let _ = cleanup.await;
        }
        let _ = result_sender.send(outcome);
    });
    (result, EnrollmentWatcher(watcher))
}
