use runne_provider::DispatchError;
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

pub(super) async fn wait<T>(
    effect: impl Future<Output = Result<T, DispatchError>>,
    mut current: impl FnMut() -> bool,
) -> Result<T, DispatchError> {
    if !current() {
        return Err(DispatchError::MaybeDispatched);
    }
    tokio::pin!(effect);
    let cadence = Duration::from_millis(50);
    let mut tick = futures_timer::Delay::new(cadence);
    std::future::poll_fn(|cx| {
        if Pin::new(&mut tick).poll(cx).is_ready() {
            if !current() {
                return Poll::Ready(Err(DispatchError::MaybeDispatched));
            }
            tick.reset(cadence);
            let _ = Pin::new(&mut tick).poll(cx);
        }
        effect.as_mut().poll(cx)
    })
    .await
}

pub(super) async fn cancel(
    provider: &(impl runne_provider::ProviderPort + ?Sized),
    stream: runne_provider::ProviderStreamId,
) {
    let cancel = provider.cancel(runne_provider::CancelRequest::new(stream));
    tokio::pin!(cancel);
    let mut timeout = futures_timer::Delay::new(Duration::from_secs(1));
    std::future::poll_fn(|cx| {
        if Pin::new(&mut timeout).poll(cx).is_ready() {
            return Poll::Ready(());
        }
        cancel.as_mut().poll(cx).map(|_| ())
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn pending_effect_revalidation_supports_non_tokio_executor() {
        let mut checks = 0;
        let result = futures::executor::block_on(wait(
            std::future::pending::<Result<(), DispatchError>>(),
            || {
                checks += 1;
                checks == 1
            },
        ));
        assert_eq!(result, Err(DispatchError::MaybeDispatched));
    }

    #[tokio::test]
    async fn revoked_pending_effect_is_dropped_without_retry() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(Arc::clone(&dropped));
        let effect = async move {
            let _guard = guard;
            std::future::pending::<Result<(), DispatchError>>().await
        };
        let mut checks = 0;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait(effect, || {
                checks += 1;
                checks == 1
            }),
        )
        .await;
        assert!(matches!(result, Ok(Err(DispatchError::MaybeDispatched))));
        assert!(dropped.load(Ordering::SeqCst));
    }
}
