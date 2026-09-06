use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::CredentialServiceXpcError;
use crate::client::native::call_state::{ConnectionInvalidator, NativeCallState, UnknownTerminal};
use crate::frame::{FrameDropWitness, NativeReplyFrame, NativeRequestFrame};

const CANARY: &str = "runne-d1-1c-xpc-canary-c824d9";
#[derive(Default)]
struct InvalidationWitness(AtomicUsize);

impl ConnectionInvalidator for InvalidationWitness {
    fn invalidate(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}
struct CallFixture {
    call: NativeCallState,
    reply: crate::client::native::call_state::NativeReplyHandle,
    receiver: oneshot::Receiver<Result<NativeReplyFrame, CredentialServiceXpcError>>,
    request_drops: Arc<AtomicUsize>,
    terminal_events: Arc<AtomicUsize>,
    invalidations: Arc<InvalidationWitness>,
}

fn call_fixture() -> CallFixture {
    call_fixture_with(Arc::new(InvalidationWitness::default()))
}

fn call_fixture_with(invalidations: Arc<InvalidationWitness>) -> CallFixture {
    let request_drops = Arc::new(AtomicUsize::new(0));
    let terminal_events = Arc::new(AtomicUsize::new(0));
    let invalidator: Arc<dyn ConnectionInvalidator> = invalidations.clone();
    let request = NativeRequestFrame::new_observed(
        Zeroizing::new(CANARY.as_bytes().to_vec()),
        FrameDropWitness::new(Arc::clone(&request_drops)),
    )
    .unwrap();
    let (sender, receiver) = oneshot::channel();
    let call =
        NativeCallState::new_observed(request, sender, &invalidator, Arc::clone(&terminal_events));
    let reply = call.reply_handle();
    CallFixture {
        call,
        reply,
        receiver,
        request_drops,
        terminal_events,
        invalidations,
    }
}

fn observed_reply(drops: Arc<AtomicUsize>) -> NativeReplyFrame {
    NativeReplyFrame::new_observed(
        Zeroizing::new(CANARY.as_bytes().to_vec()),
        FrameDropWitness::new(drops),
    )
    .unwrap()
}

#[test]
fn successful_reply_releases_each_repository_frame_once() {
    let mut fixture = call_fixture();
    let reply_drops = Arc::new(AtomicUsize::new(0));

    fixture
        .reply
        .deliver(Ok(observed_reply(Arc::clone(&reply_drops))));
    let reply = fixture.receiver.try_recv().unwrap().unwrap();
    fixture.call.accept_reply();

    assert_eq!(fixture.terminal_events.load(Ordering::Acquire), 1);
    assert_eq!(fixture.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(reply_drops.load(Ordering::Acquire), 0);
    assert_eq!(fixture.invalidations.0.load(Ordering::Acquire), 0);
    drop(reply);
    assert_eq!(reply_drops.load(Ordering::Acquire), 1);
    drop(fixture.call);
    assert_eq!(fixture.invalidations.0.load(Ordering::Acquire), 0);
}

#[test]
fn every_outcome_unknown_terminal_releases_request_and_late_reply_once() {
    for terminal in [
        UnknownTerminal::Timeout,
        UnknownTerminal::Cancelled,
        UnknownTerminal::Interrupted,
        UnknownTerminal::Invalidated,
        UnknownTerminal::DispatchError,
        UnknownTerminal::MalformedReply,
    ] {
        let mut fixture = call_fixture();
        let reply_drops = Arc::new(AtomicUsize::new(0));

        let callback_terminal = matches!(
            terminal,
            UnknownTerminal::DispatchError | UnknownTerminal::MalformedReply
        );
        if callback_terminal {
            fixture.reply.deliver_unknown(terminal);
        } else {
            fixture.call.close_unknown(terminal);
        }
        if callback_terminal {
            assert!(matches!(
                fixture.receiver.try_recv().unwrap(),
                Err(CredentialServiceXpcError::OutcomeUnknown)
            ));
        }
        fixture
            .reply
            .deliver(Ok(observed_reply(Arc::clone(&reply_drops))));

        assert_eq!(fixture.terminal_events.load(Ordering::Acquire), 1);
        assert_eq!(fixture.request_drops.load(Ordering::Acquire), 1);
        assert_eq!(reply_drops.load(Ordering::Acquire), 1);
        assert_eq!(fixture.invalidations.0.load(Ordering::Acquire), 1);
    }
}

#[test]
fn receiver_close_drops_reply_and_fails_connection_closed() {
    let fixture = call_fixture();
    let reply_drops = Arc::new(AtomicUsize::new(0));
    drop(fixture.receiver);

    fixture
        .reply
        .deliver(Ok(observed_reply(Arc::clone(&reply_drops))));

    assert_eq!(fixture.terminal_events.load(Ordering::Acquire), 1);
    assert_eq!(fixture.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(reply_drops.load(Ordering::Acquire), 1);
    assert_eq!(fixture.invalidations.0.load(Ordering::Acquire), 1);
}

#[test]
fn timeout_after_reply_is_queued_invalidates_fail_closed() {
    let fixture = call_fixture();
    let reply_drops = Arc::new(AtomicUsize::new(0));
    fixture
        .reply
        .deliver(Ok(observed_reply(Arc::clone(&reply_drops))));
    fixture.call.close_unknown(UnknownTerminal::Timeout);
    assert_eq!(fixture.invalidations.0.load(Ordering::Acquire), 1);
    drop(fixture.receiver);
    drop(fixture.call);

    assert_eq!(fixture.terminal_events.load(Ordering::Acquire), 1);
    assert_eq!(fixture.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(reply_drops.load(Ordering::Acquire), 1);
    assert_eq!(fixture.invalidations.0.load(Ordering::Acquire), 1);
}

#[test]
fn dropping_dispatched_call_is_single_terminal_and_fail_closed() {
    let fixture = call_fixture();
    let reply_drops = Arc::new(AtomicUsize::new(0));
    let reply = fixture.reply;
    let request_drops = Arc::clone(&fixture.request_drops);
    let terminal_events = Arc::clone(&fixture.terminal_events);
    let invalidations = Arc::clone(&fixture.invalidations);
    drop(fixture.call);

    reply.deliver(Ok(observed_reply(Arc::clone(&reply_drops))));

    assert_eq!(terminal_events.load(Ordering::Acquire), 1);
    assert_eq!(request_drops.load(Ordering::Acquire), 1);
    assert_eq!(reply_drops.load(Ordering::Acquire), 1);
    assert_eq!(invalidations.0.load(Ordering::Acquire), 1);
}

#[test]
fn invalidating_one_call_fails_concurrent_calls_closed_without_double_terminal() {
    let connection = Arc::new(InvalidationWitness::default());
    let first = call_fixture_with(Arc::clone(&connection));
    let second = call_fixture_with(connection);

    // NativeClient broadcasts the shared connection event to both dispatched calls.
    first.call.close_unknown(UnknownTerminal::Timeout);
    second.call.close_unknown(UnknownTerminal::Invalidated);
    second.call.close_unknown(UnknownTerminal::Interrupted);

    assert_eq!(first.terminal_events.load(Ordering::Acquire), 1);
    assert_eq!(second.terminal_events.load(Ordering::Acquire), 1);
    assert_eq!(first.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(second.request_drops.load(Ordering::Acquire), 1);
    assert_eq!(first.invalidations.0.load(Ordering::Acquire), 2);
    assert_eq!(second.invalidations.0.load(Ordering::Acquire), 2);
}

#[test]
fn malformed_frames_and_errors_are_bounded_and_closed() {
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
    let request_error = |result| match result {
        Err(error) => error,
        Ok(_) => panic!("malformed request frame must be rejected"),
    };
    let reply_error = |result| match result {
        Err(error) => error,
        Ok(_) => panic!("malformed reply frame must be rejected"),
    };
    let errors = [
        request_error(crate::frame::native::copy_request(&empty)),
        reply_error(crate::frame::native::copy_reply(&empty)),
        request_error(crate::frame::native::copy_request(&oversized)),
        reply_error(crate::frame::native::copy_reply(&oversized)),
    ];

    for error in errors {
        assert_eq!(
            error.to_string(),
            "credential service native transport failed"
        );
        assert!(!format!("{error:?}").contains(CANARY));
        assert!(!error.to_string().contains(CANARY));
    }
}

struct ReentrantInvalidator {
    count: AtomicUsize,
    reply: Mutex<Option<crate::client::native::call_state::NativeReplyHandle>>,
}

impl ConnectionInvalidator for ReentrantInvalidator {
    fn invalidate(&self) {
        self.count.fetch_add(1, Ordering::AcqRel);
        let reply = self
            .reply
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(reply) = reply {
            reply.deliver_unknown(UnknownTerminal::Invalidated);
        }
    }
}

#[test]
fn connection_invalidation_can_reenter_without_deadlock_or_double_terminal() {
    let request_drops = Arc::new(AtomicUsize::new(0));
    let terminal_events = Arc::new(AtomicUsize::new(0));
    let invalidations = Arc::new(ReentrantInvalidator {
        count: AtomicUsize::new(0),
        reply: Mutex::new(None),
    });
    let invalidator: Arc<dyn ConnectionInvalidator> = invalidations.clone();
    let request = NativeRequestFrame::new_observed(
        Zeroizing::new(CANARY.as_bytes().to_vec()),
        FrameDropWitness::new(Arc::clone(&request_drops)),
    )
    .unwrap();
    let (sender, _receiver) = oneshot::channel();
    let call =
        NativeCallState::new_observed(request, sender, &invalidator, Arc::clone(&terminal_events));
    *invalidations
        .reply
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(call.reply_handle());

    call.close_unknown(UnknownTerminal::Timeout);

    assert_eq!(terminal_events.load(Ordering::Acquire), 1);
    assert_eq!(request_drops.load(Ordering::Acquire), 1);
    assert_eq!(invalidations.count.load(Ordering::Acquire), 1);
}
