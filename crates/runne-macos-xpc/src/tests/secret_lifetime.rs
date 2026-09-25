use std::future::{Future, poll_fn};
use std::sync::{Arc, atomic::Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServiceCancellation,
};
use zeroize::Zeroizing;

use crate::CredentialServiceXpcError;
use crate::client::native::exchange::{self, ConnectionEvent};

#[path = "secret_lifetime/support.rs"]
mod support;
use support::{CANARY, Counts, TestConnection, assert_unknown, await_call, context, spawn_call};

#[tokio::test]
async fn success_accepts_reply_and_avoids_invalidation() {
    let connection = TestConnection::new();
    let counts = Counts::default();
    let call = spawn_call(
        Arc::clone(&connection),
        context(Duration::from_secs(1), CredentialServiceCancellation::new()),
        &counts,
    );
    connection.wait_for_dispatches(1).await;
    connection.callback().valid_reply(counts.reply());
    let reply = await_call(call).await.unwrap();
    drop(reply);

    assert_eq!(counts.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.reply_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.terminals.load(Ordering::Acquire), 1);
    assert_eq!(connection.invalidations.load(Ordering::Acquire), 0);
}

async fn run_timeout_or_cancel(cancel: bool) {
    let connection = TestConnection::new();
    let counts = Counts::default();
    let cancellation = CredentialServiceCancellation::new();
    let call = spawn_call(
        Arc::clone(&connection),
        context(
            if cancel {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(30)
            },
            cancellation.clone(),
        ),
        &counts,
    );
    connection.wait_for_dispatches(1).await;
    let callback = connection.callback();
    if cancel {
        cancellation.cancel();
    }
    assert_unknown(&await_call(call).await);
    callback.valid_reply(counts.reply());
    assert_eq!(counts.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.reply_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.terminals.load(Ordering::Acquire), 1);
    assert_eq!(connection.invalidations.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn timeout_after_dispatch_is_outcome_unknown() {
    run_timeout_or_cancel(false).await;
}

#[tokio::test]
async fn cancellation_after_dispatch_is_outcome_unknown() {
    run_timeout_or_cancel(true).await;
}

async fn run_connection_event(event: ConnectionEvent) {
    let connection = TestConnection::new();
    let counts = Counts::default();
    let call = spawn_call(
        Arc::clone(&connection),
        context(Duration::from_secs(1), CredentialServiceCancellation::new()),
        &counts,
    );
    connection.wait_for_dispatches(1).await;
    let callback = connection.callback();
    connection.signal(event);
    assert_unknown(&await_call(call).await);
    callback.valid_reply(counts.reply());
    assert_eq!(counts.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.reply_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.terminals.load(Ordering::Acquire), 1);
    assert_eq!(connection.invalidations.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn interruption_broadcast_is_outcome_unknown() {
    run_connection_event(ConnectionEvent::Interrupted).await;
}

#[tokio::test]
async fn invalidation_broadcast_is_outcome_unknown() {
    run_connection_event(ConnectionEvent::Invalidated).await;
}

enum CallbackFailure {
    Dispatch,
    Proxy,
    Malformed,
    Sender,
}

async fn run_callback_failure(failure: CallbackFailure) {
    let connection = TestConnection::new();
    let counts = Counts::default();
    connection
        .broadcast_invalidation
        .store(false, Ordering::Release);
    connection.dispatch_error.store(
        matches!(failure, CallbackFailure::Dispatch),
        Ordering::Release,
    );
    let call = spawn_call(
        Arc::clone(&connection),
        context(Duration::from_secs(1), CredentialServiceCancellation::new()),
        &counts,
    );
    connection.wait_for_dispatches(1).await;
    if !matches!(failure, CallbackFailure::Dispatch) {
        let callback = connection.callback();
        match failure {
            CallbackFailure::Proxy => callback.proxy_error(),
            CallbackFailure::Malformed => {
                callback.native_reply(Err(CredentialServiceXpcError::InvalidReply));
            }
            CallbackFailure::Sender => callback.simulate_sender_loss(),
            CallbackFailure::Dispatch => unreachable!(),
        }
    }
    assert_unknown(&await_call(call).await);
    assert_eq!(counts.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.terminals.load(Ordering::Acquire), 1);
    assert_eq!(connection.invalidations.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn objective_c_dispatch_exception_equivalent_is_outcome_unknown() {
    run_callback_failure(CallbackFailure::Dispatch).await;
}

#[tokio::test]
async fn proxy_error_callback_is_outcome_unknown() {
    run_callback_failure(CallbackFailure::Proxy).await;
}

#[tokio::test]
async fn malformed_reply_callback_collapses_to_outcome_unknown() {
    run_callback_failure(CallbackFailure::Malformed).await;
}

#[tokio::test]
async fn sender_loss_reaches_receiver_close_outcome_unknown() {
    run_callback_failure(CallbackFailure::Sender).await;
}

#[tokio::test]
async fn dropped_exchange_future_releases_request_and_late_reply() {
    let connection = TestConnection::new();
    let counts = Counts::default();
    let call = spawn_call(
        Arc::clone(&connection),
        context(Duration::from_secs(1), CredentialServiceCancellation::new()),
        &counts,
    );
    connection.wait_for_dispatches(1).await;
    let callback = connection.callback();
    call.abort();
    assert!(call.await.is_err());
    callback.valid_reply(counts.reply());

    assert_eq!(counts.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.reply_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.terminals.load(Ordering::Acquire), 1);
    assert_eq!(connection.invalidations.load(Ordering::Acquire), 1);
}

async fn run_queued_reply_race(timeout: bool) {
    let connection = TestConnection::new();
    let counts = Counts::default();
    let deadline = Instant::now() + Duration::from_millis(20);
    let future = exchange::exchange_observed(
        Arc::clone(&connection),
        Zeroizing::new(CANARY.as_bytes().to_vec()),
        CredentialServiceCallContext::new(deadline, CredentialServiceCancellation::new()),
        counts.witnesses(),
    );
    let mut future = Box::pin(future);
    poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("call must remain dispatched"),
    })
    .await;
    connection.callback().valid_reply(counts.reply());
    if timeout {
        tokio::time::sleep_until(deadline.into()).await;
        assert_unknown(&future.await);
    } else {
        drop(future);
    }
    assert_eq!(counts.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.reply_drops.load(Ordering::Acquire), 1);
    assert_eq!(counts.terminals.load(Ordering::Acquire), 1);
    assert_eq!(connection.invalidations.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn queued_reply_racing_timeout_invalidates_fail_closed() {
    run_queued_reply_race(true).await;
}

#[tokio::test]
async fn queued_reply_racing_future_drop_invalidates_fail_closed() {
    run_queued_reply_race(false).await;
}

#[tokio::test]
async fn one_invalidation_broadcast_closes_both_concurrent_exchanges() {
    let connection = TestConnection::new();
    let first = Counts::default();
    let second = Counts::default();
    let first_call = spawn_call(
        Arc::clone(&connection),
        context(
            Duration::from_millis(30),
            CredentialServiceCancellation::new(),
        ),
        &first,
    );
    let second_call = spawn_call(
        Arc::clone(&connection),
        context(Duration::from_secs(1), CredentialServiceCancellation::new()),
        &second,
    );
    connection.wait_for_dispatches(2).await;
    assert_unknown(&await_call(first_call).await);
    assert_unknown(&await_call(second_call).await);

    assert_eq!(first.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(second.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(first.terminals.load(Ordering::Acquire), 1);
    assert_eq!(second.terminals.load(Ordering::Acquire), 1);
    assert_eq!(connection.invalidations.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn predispatch_cancel_and_expiry_remain_definitive_without_invalidation() {
    for cancelled in [false, true] {
        let connection = TestConnection::new();
        let counts = Counts::default();
        let cancellation = CredentialServiceCancellation::new();
        if cancelled {
            cancellation.cancel();
        }
        let deadline = if cancelled {
            Instant::now() + Duration::from_secs(1)
        } else {
            Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap()
        };
        let result = exchange::exchange_observed(
            Arc::clone(&connection),
            Zeroizing::new(CANARY.as_bytes().to_vec()),
            CredentialServiceCallContext::new(deadline, cancellation),
            counts.witnesses(),
        )
        .await;
        assert!(matches!(
            result,
            Err(CredentialServiceXpcError::Cancelled | CredentialServiceXpcError::TimedOut)
        ));
        assert_eq!(connection.dispatch_count(), 0);
        assert_eq!(connection.invalidations.load(Ordering::Acquire), 0);
    }
}
