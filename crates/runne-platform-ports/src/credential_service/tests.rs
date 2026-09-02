use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use super::*;

struct Desktop;
impl CredentialServiceDesktopPort for Desktop {
    fn challenge(
        &self,
        _request: CredentialServiceDesktopRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply> {
        Box::pin(async { Ok(desktop_reply()) })
    }

    fn register(
        &self,
        _request: CredentialServiceDesktopRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply> {
        Box::pin(async { Ok(desktop_reply()) })
    }
}

struct Runtime;
impl CredentialServiceRuntimePort for Runtime {
    fn arm_mutation(
        &self,
        _request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async { Ok(runtime_reply()) })
    }

    fn read_metadata(
        &self,
        _request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async { Ok(runtime_reply()) })
    }

    fn read_material(
        &self,
        _request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async { Ok(runtime_reply()) })
    }
}

struct Writer;
impl CredentialServiceWriterPort for Writer {
    fn consume_mutation(
        &self,
        _request: CredentialServiceWriterRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceWriterReply> {
        Box::pin(async { Ok(writer_reply()) })
    }
}

fn context(cancellation: CredentialServiceCancellation) -> CredentialServiceCallContext {
    CredentialServiceCallContext::new(std::time::Instant::now(), cancellation)
}

fn desktop_request() -> CredentialServiceDesktopRequest {
    CredentialServiceDesktopRequest::from_zeroizing(zeroize::Zeroizing::new(vec![1])).unwrap()
}
fn desktop_reply() -> CredentialServiceDesktopReply {
    CredentialServiceDesktopReply::from_zeroizing(zeroize::Zeroizing::new(vec![2])).unwrap()
}
fn runtime_request() -> CredentialServiceRuntimeRequest {
    CredentialServiceRuntimeRequest::from_zeroizing(zeroize::Zeroizing::new(vec![3])).unwrap()
}
fn runtime_reply() -> CredentialServiceRuntimeReply {
    CredentialServiceRuntimeReply::from_zeroizing(zeroize::Zeroizing::new(vec![4])).unwrap()
}
fn writer_request() -> CredentialServiceWriterRequest {
    CredentialServiceWriterRequest::from_zeroizing(zeroize::Zeroizing::new(vec![5])).unwrap()
}
fn writer_reply() -> CredentialServiceWriterReply {
    CredentialServiceWriterReply::from_zeroizing(zeroize::Zeroizing::new(vec![6])).unwrap()
}

#[test]
fn role_ports_expose_only_their_bounded_operations() {
    let cancellation = CredentialServiceCancellation::new();
    let desktop = Desktop;
    drop(desktop.challenge(desktop_request(), context(cancellation.clone())));
    drop(desktop.register(desktop_request(), context(cancellation.clone())));

    let runtime = Runtime;
    drop(runtime.arm_mutation(runtime_request(), context(cancellation.clone())));
    drop(runtime.read_metadata(runtime_request(), context(cancellation.clone())));
    drop(runtime.read_material(runtime_request(), context(cancellation.clone())));

    let writer = Writer;
    drop(writer.consume_mutation(writer_request(), context(cancellation)));
}

struct FlagWake(AtomicBool);

impl Wake for FlagWake {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

#[test]
fn cancellation_wakes_an_already_pending_observer() {
    let cancellation = CredentialServiceCancellation::new();
    let mut pending = pin!(cancellation.cancelled());
    let woke = Arc::new(FlagWake(AtomicBool::new(false)));
    let waker = Waker::from(Arc::clone(&woke));
    let mut task_context = Context::from_waker(&waker);
    assert_eq!(pending.as_mut().poll(&mut task_context), Poll::Pending);

    cancellation.cancel();

    assert!(woke.0.load(Ordering::Acquire));
    assert_eq!(pending.as_mut().poll(&mut task_context), Poll::Ready(()));
}

#[test]
fn dropped_cancellation_observers_release_their_wakers() {
    let cancellation = CredentialServiceCancellation::new();
    for _ in 0..1_000 {
        let mut pending = pin!(cancellation.cancelled());
        let woke = Arc::new(FlagWake(AtomicBool::new(false)));
        let waker = Waker::from(woke);
        let mut task_context = Context::from_waker(&waker);
        assert_eq!(pending.as_mut().poll(&mut task_context), Poll::Pending);
    }
    assert_eq!(cancellation.test_waiter_count(), 0);
}

#[test]
fn transport_frames_are_bounded_and_zeroizing() {
    let bytes = zeroize::Zeroizing::new(vec![3]);
    let allocation = bytes.as_ptr();
    let frame = CredentialServiceRuntimeRequest::from_zeroizing(bytes).unwrap();
    assert_eq!(frame.with_bytes(<[u8]>::to_vec), vec![3]);
    assert_eq!(frame.with_bytes(<[u8]>::as_ptr), allocation);
    assert!(
        CredentialServiceRuntimeRequest::from_zeroizing(zeroize::Zeroizing::new(Vec::new()))
            .is_err()
    );
    assert!(
        CredentialServiceRuntimeRequest::from_zeroizing(zeroize::Zeroizing::new(vec![
            0;
            MAX_CREDENTIAL_SERVICE_FRAME_BYTES
                + 1
        ]))
        .is_err()
    );
}

#[test]
fn cancellation_is_shared_without_raw_platform_state() {
    let cancellation = CredentialServiceCancellation::new();
    let observer = cancellation.clone();
    assert!(!observer.is_cancelled());
    cancellation.cancel();
    assert!(observer.is_cancelled());
    assert_eq!(
        format!("{observer:?}"),
        "CredentialServiceCancellation(cancelled)"
    );
}

#[test]
fn call_context_retains_exact_deadline_and_cancellation() {
    let cancellation = CredentialServiceCancellation::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    let context = CredentialServiceCallContext::new(deadline, cancellation.clone());
    assert_eq!(context.deadline(), deadline);
    assert!(!context.cancellation().is_cancelled());
    cancellation.cancel();
    assert!(context.cancellation().is_cancelled());
}

#[test]
fn failures_are_closed_and_do_not_carry_native_details() {
    for error in [
        CredentialServicePortError::Rejected,
        CredentialServicePortError::Unsupported,
        CredentialServicePortError::Unavailable,
        CredentialServicePortError::TimedOut,
        CredentialServicePortError::Cancelled,
        CredentialServicePortError::Interrupted,
        CredentialServicePortError::Invalidated,
        CredentialServicePortError::InvalidReply,
        CredentialServicePortError::OutcomeUnknown,
    ] {
        assert_eq!(error.to_string(), "credential service call failed");
        assert!(!format!("{error:?}").contains('/'));
    }
}

#[test]
fn cancellation_token_is_send_sync_and_shared() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<CredentialServiceCancellation>();
    require_send_sync::<CredentialServiceCallContext>();
    let cancellation = Arc::new(CredentialServiceCancellation::new());
    let observer = Arc::clone(&cancellation);
    std::thread::spawn(move || observer.cancel())
        .join()
        .unwrap();
    assert!(cancellation.is_cancelled());
}
