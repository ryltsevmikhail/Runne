use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServiceCancellation,
};
use tokio::sync::{Notify, watch};
use zeroize::Zeroizing;

use crate::CredentialServiceXpcError;
use crate::client::native::call_state::ConnectionInvalidator;
use crate::client::native::exchange::{
    self, ConnectionEvent, ExchangeConnection, NativeCallbacks, TestWitnesses,
};
use crate::frame::{FrameDropWitness, NativeReplyFrame, NativeRequestFrame};

pub(super) const CANARY: &str = "runne-d1-1c-xpc-canary-c824d9";

#[derive(Default)]
pub(super) struct Counts {
    pub(super) request_drops: Arc<AtomicUsize>,
    pub(super) reply_drops: Arc<AtomicUsize>,
    pub(super) terminals: Arc<AtomicUsize>,
}

impl Counts {
    pub(super) fn witnesses(&self) -> TestWitnesses {
        TestWitnesses::new(
            FrameDropWitness::new(Arc::clone(&self.request_drops)),
            Arc::clone(&self.terminals),
        )
    }

    pub(super) fn reply(&self) -> NativeReplyFrame {
        NativeReplyFrame::new_observed(
            Zeroizing::new(CANARY.as_bytes().to_vec()),
            FrameDropWitness::new(Arc::clone(&self.reply_drops)),
        )
        .unwrap()
    }
}

pub(super) struct TestConnection {
    events: watch::Sender<ConnectionEvent>,
    callbacks: Mutex<VecDeque<NativeCallbacks>>,
    dispatched: AtomicUsize,
    pub(super) dispatch_error: AtomicBool,
    invalidated: AtomicBool,
    pub(super) invalidations: AtomicUsize,
    pub(super) broadcast_invalidation: AtomicBool,
    notification: Notify,
}

impl TestConnection {
    pub(super) fn new() -> Arc<Self> {
        let (events, _) = watch::channel(ConnectionEvent::Active);
        Arc::new(Self {
            events,
            callbacks: Mutex::new(VecDeque::new()),
            dispatched: AtomicUsize::new(0),
            dispatch_error: AtomicBool::new(false),
            invalidated: AtomicBool::new(false),
            invalidations: AtomicUsize::new(0),
            broadcast_invalidation: AtomicBool::new(true),
            notification: Notify::new(),
        })
    }

    pub(super) async fn wait_for_dispatches(&self, expected: usize) {
        tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                let notified = self.notification.notified();
                if self.dispatched.load(Ordering::Acquire) >= expected {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("dispatch route must beat the outer test deadline");
    }

    pub(super) fn callback(&self) -> NativeCallbacks {
        self.callbacks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
            .expect("dispatched callback")
    }

    pub(super) fn signal(&self, event: ConnectionEvent) {
        self.events.send_replace(event);
    }

    pub(super) fn dispatch_count(&self) -> usize {
        self.dispatched.load(Ordering::Acquire)
    }
}

impl ConnectionInvalidator for TestConnection {
    fn invalidate(&self) {
        if !self.invalidated.swap(true, Ordering::AcqRel) {
            self.invalidations.fetch_add(1, Ordering::AcqRel);
            if self.broadcast_invalidation.load(Ordering::Acquire) {
                self.events.send_replace(ConnectionEvent::Invalidated);
            }
        }
    }
}

impl ExchangeConnection for TestConnection {
    type PreparedRequest = ();

    fn subscribe(&self) -> watch::Receiver<ConnectionEvent> {
        self.events.subscribe()
    }

    fn prepare(&self, _request: &NativeRequestFrame) -> Self::PreparedRequest {}

    fn dispatch(
        &self,
        _request: Self::PreparedRequest,
        callbacks: NativeCallbacks,
    ) -> Result<(), ()> {
        self.dispatched.fetch_add(1, Ordering::AcqRel);
        self.notification.notify_waiters();
        if self.dispatch_error.load(Ordering::Acquire) {
            return Err(());
        }
        self.callbacks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(callbacks);
        Ok(())
    }
}

pub(super) fn context(
    after: Duration,
    cancellation: CredentialServiceCancellation,
) -> CredentialServiceCallContext {
    CredentialServiceCallContext::new(Instant::now() + after, cancellation)
}

pub(super) fn spawn_call(
    connection: Arc<TestConnection>,
    context: CredentialServiceCallContext,
    counts: &Counts,
) -> tokio::task::JoinHandle<Result<NativeReplyFrame, CredentialServiceXpcError>> {
    tokio::spawn(exchange::exchange_observed(
        connection,
        Zeroizing::new(CANARY.as_bytes().to_vec()),
        context,
        counts.witnesses(),
    ))
}

pub(super) async fn await_call(
    call: tokio::task::JoinHandle<Result<NativeReplyFrame, CredentialServiceXpcError>>,
) -> Result<NativeReplyFrame, CredentialServiceXpcError> {
    tokio::time::timeout(Duration::from_millis(200), call)
        .await
        .expect("terminal route must beat the outer test deadline")
        .expect("exchange task must not panic")
}

pub(super) fn assert_unknown(result: &Result<NativeReplyFrame, CredentialServiceXpcError>) {
    assert!(matches!(
        result,
        Err(CredentialServiceXpcError::OutcomeUnknown)
    ));
}

#[test]
fn malformed_native_data_is_bounded_and_error_text_is_closed() {
    let empty = objc2_foundation::NSData::from_vec(Vec::new());
    let oversized = objc2_foundation::NSData::from_vec(
        CANARY
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(runne_platform_ports::credential_service::MAX_CREDENTIAL_SERVICE_FRAME_BYTES + 1)
            .collect(),
    );
    let errors = [
        crate::frame::native::copy_request(&empty).err().unwrap(),
        crate::frame::native::copy_reply(&empty).err().unwrap(),
        crate::frame::native::copy_request(&oversized)
            .err()
            .unwrap(),
        crate::frame::native::copy_reply(&oversized).err().unwrap(),
    ];
    for error in errors {
        assert_eq!(
            error.to_string(),
            "credential service native transport failed"
        );
        assert!(!format!("{error:?}").contains(CANARY));
    }
}
