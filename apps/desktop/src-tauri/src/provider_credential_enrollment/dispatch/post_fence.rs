use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;

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
) -> Result<
    (
        tokio::sync::oneshot::Receiver<Result<T, E>>,
        EnrollmentWatcher,
    ),
    E,
>
where
    W: FnOnce() -> O + Send + 'static,
    O: Future<Output = Result<T, E>> + Send + 'static,
    X: FnOnce() -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
    J: Fn() -> E + Send + Sync + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    spawn_owner_inner(
        work,
        cleanup,
        join_failure,
        std::future::ready(()),
        None,
        try_spawn,
    )
}

type WatcherFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

fn spawn_owner_inner<W, O, X, F, J, B, S, T, E>(
    work: W,
    cleanup: X,
    join_failure: J,
    ownership_barrier: B,
    work_observer: Option<tokio::sync::oneshot::Sender<tokio::task::AbortHandle>>,
    spawn_watcher: S,
) -> Result<
    (
        tokio::sync::oneshot::Receiver<Result<T, E>>,
        EnrollmentWatcher,
    ),
    E,
>
where
    W: FnOnce() -> O + Send + 'static,
    O: Future<Output = Result<T, E>> + Send + 'static,
    X: FnOnce() -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
    J: Fn() -> E + Send + Sync + 'static,
    B: Future<Output = ()> + Send + 'static,
    S: FnOnce(WatcherFuture) -> Result<tauri::async_runtime::JoinHandle<()>, ()>,
    T: Send + 'static,
    E: Send + 'static,
{
    let (result_sender, result) = tokio::sync::oneshot::channel();
    let join_failure = Arc::new(join_failure);
    let watcher_failure = Arc::clone(&join_failure);
    let watcher = Box::pin(async move {
        let cleanup = CleanupOwner::new(cleanup);
        ownership_barrier.await;
        let outcome = match try_spawn(async move { work().await }) {
            Ok(work) => {
                if let Some(observer) = work_observer {
                    let _ = observer.send(work.inner().abort_handle());
                }
                work.await.unwrap_or_else(|_| Err(watcher_failure()))
            }
            Err(()) => Err(watcher_failure()),
        };
        if outcome.is_err() {
            cleanup.run().await;
        }
        let _ = result_sender.send(outcome);
    });
    spawn_watcher(watcher)
        .map(|watcher| (result, EnrollmentWatcher(watcher)))
        .map_err(|()| join_failure())
}

struct CleanupOwner<X>(Option<X>);

impl<X> CleanupOwner<X> {
    const fn new(cleanup: X) -> Self {
        Self(Some(cleanup))
    }
}

impl<X, F> CleanupOwner<X>
where
    X: FnOnce() -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    async fn run(mut self) {
        let cleanup = self.0.take().expect("watcher cleanup owner");
        if let Ok(task) = try_spawn(async move { cleanup().await }) {
            let _ = task.await;
        }
    }
}

fn try_spawn<F>(future: F) -> Result<tauri::async_runtime::JoinHandle<F::Output>, ()>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    std::panic::catch_unwind(AssertUnwindSafe(|| tauri::async_runtime::spawn(future)))
        .map_err(|_| ())
}

#[cfg(test)]
pub(super) struct WatcherTestControl {
    ownership_barrier: WatcherFuture,
    work_observer: Option<tokio::sync::oneshot::Sender<tokio::task::AbortHandle>>,
    fail_watcher_spawn: bool,
}

#[cfg(test)]
impl WatcherTestControl {
    pub(super) fn hold_after_claim(
        claimed: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) -> Self {
        Self {
            ownership_barrier: Box::pin(async move {
                let _ = claimed.send(());
                let _ = release.await;
            }),
            work_observer: None,
            fail_watcher_spawn: false,
        }
    }

    pub(super) fn observe_work(
        observer: tokio::sync::oneshot::Sender<tokio::task::AbortHandle>,
    ) -> Self {
        Self {
            ownership_barrier: Box::pin(std::future::ready(())),
            work_observer: Some(observer),
            fail_watcher_spawn: false,
        }
    }

    pub(super) fn fail_watcher_spawn() -> Self {
        Self {
            ownership_barrier: Box::pin(std::future::ready(())),
            work_observer: None,
            fail_watcher_spawn: true,
        }
    }
}

#[cfg(test)]
pub(super) fn spawn_pre_fence_enrollment_owner_controlled<W, O, X, F, J, T, E>(
    work: W,
    cleanup: X,
    join_failure: J,
    control: WatcherTestControl,
) -> Result<
    (
        tokio::sync::oneshot::Receiver<Result<T, E>>,
        EnrollmentWatcher,
    ),
    E,
>
where
    W: FnOnce() -> O + Send + 'static,
    O: Future<Output = Result<T, E>> + Send + 'static,
    X: FnOnce() -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
    J: Fn() -> E + Send + Sync + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let fail = control.fail_watcher_spawn;
    spawn_owner_inner(
        work,
        cleanup,
        join_failure,
        control.ownership_barrier,
        control.work_observer,
        move |future| if fail { Err(()) } else { try_spawn(future) },
    )
}
