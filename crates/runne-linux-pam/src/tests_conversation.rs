use std::collections::VecDeque;
use std::ffi::{CString, c_int};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::conversation::{
    ConversationState, PamConversationHandler, PamMessageKind, test_invoke_conversation,
};
use super::ffi;
use super::response_buffer::test_live_allocations;
use super::transaction::test_require_successful_interaction;
use super::{PamCancellation, PamInteractionError};

const ECHO_OFF: c_int = 1;
const ECHO_ON: c_int = 2;
const INFORMATION: c_int = 4;

enum Reply {
    Secret(Vec<u8>),
    Cancel,
    Reject,
    Panic,
}

struct TestHandler {
    replies: Mutex<VecDeque<Reply>>,
    calls: AtomicUsize,
}

impl TestHandler {
    fn new(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().collect()),
            calls: AtomicUsize::new(0),
        }
    }
}

impl PamConversationHandler for TestHandler {
    fn present(
        &self,
        _kind: PamMessageKind,
        _message: &str,
        _cancellation: &PamCancellation,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, PamInteractionError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let reply = self.replies.lock().expect("reply mutex").pop_front();
        match reply {
            Some(Reply::Secret(secret)) => Ok(Some(Zeroizing::new(secret))),
            Some(Reply::Cancel) => Err(PamInteractionError::Cancelled),
            Some(Reply::Reject) => Err(PamInteractionError::Rejected),
            Some(Reply::Panic) => panic!("synthetic callback panic"),
            None => Ok(None),
        }
    }
}

fn invoke(
    messages: &[(c_int, CString)],
    handler: Arc<TestHandler>,
    cancel: bool,
) -> (
    c_int,
    Option<super::response_buffer::TestResponse>,
    Box<ConversationState>,
) {
    let cancellation = PamCancellation::new();
    if cancel {
        cancellation.cancel();
    }
    let mut state = Box::new(ConversationState::new(
        handler,
        cancellation,
        Instant::now() + Duration::from_secs(2),
    ));
    let (status, response) = test_invoke_conversation(messages, &mut state);
    (status, response, state)
}

fn message(style: c_int, text: &str) -> (c_int, CString) {
    (style, CString::new(text).expect("test message has no NUL"))
}

#[test]
fn echo_off_response_is_transferred_only_after_a_nonempty_reply() {
    let handler = Arc::new(TestHandler::new([Reply::Secret(b"secret".to_vec())]));
    let (status, response, state) = invoke(
        &[message(ECHO_OFF, "Password:")],
        Arc::clone(&handler),
        false,
    );
    assert_eq!(status, ffi::PAM_SUCCESS);
    assert_eq!(state.echo_off_count(), 1);
    assert!(
        response
            .as_ref()
            .is_some_and(|owned| owned.first_response_equals(b"secret"))
    );
    drop(response);
    assert_eq!(test_live_allocations(), 0);
}

#[test]
fn unknown_and_echo_on_styles_are_rejected() {
    for style in [99, ECHO_ON] {
        let handler = Arc::new(TestHandler::new([Reply::Secret(b"secret".to_vec())]));
        let (status, response, _) = invoke(&[message(style, "Unsupported")], handler, false);
        assert_eq!(status, ffi::PAM_CONV_ERR);
        assert!(response.is_none());
    }
}

#[test]
fn zero_excessive_and_empty_message_counts_are_rejected() {
    let handler = Arc::new(TestHandler::new([]));
    let (zero_status, zero_response, zero_state) = invoke(&[], Arc::clone(&handler), false);
    assert_eq!(zero_status, ffi::PAM_CONV_ERR);
    assert!(zero_response.is_none());
    assert!(zero_state.rejected());

    let rows: Vec<_> = (0..5).map(|_| message(INFORMATION, "message")).collect();
    let (excessive_status, excessive_response, excessive_state) = invoke(&rows, handler, false);
    assert_eq!(excessive_status, ffi::PAM_CONV_ERR);
    assert!(excessive_response.is_none());
    assert!(excessive_state.rejected());
}

#[test]
fn nul_and_empty_secrets_are_rejected_without_c_allocation() {
    for secret in [b"".to_vec(), b"left\0right".to_vec()] {
        let handler = Arc::new(TestHandler::new([Reply::Secret(secret)]));
        let (status, response, state) = invoke(&[message(ECHO_OFF, "Password:")], handler, false);
        assert_eq!(status, ffi::PAM_CONV_ERR);
        assert!(response.is_none());
        assert!(state.rejected());
        assert_eq!(test_live_allocations(), 0);
    }
}

#[test]
fn cancellation_and_rejection_return_conversation_error() {
    let handler = Arc::new(TestHandler::new([Reply::Secret(b"secret".to_vec())]));
    let (status, response, state) = invoke(
        &[message(ECHO_OFF, "Password:")],
        Arc::clone(&handler),
        true,
    );
    assert_eq!(status, ffi::PAM_CONV_ERR);
    assert!(response.is_none());
    assert!(state.cancelled());
    assert_eq!(handler.calls.load(Ordering::Relaxed), 0);

    let handler = Arc::new(TestHandler::new([Reply::Cancel]));
    let (status, response, state) = invoke(&[message(ECHO_OFF, "Password:")], handler, false);
    assert_eq!(status, ffi::PAM_CONV_ERR);
    assert!(response.is_none());
    assert!(state.cancelled());

    let handler = Arc::new(TestHandler::new([Reply::Reject]));
    let (status, response, state) = invoke(&[message(ECHO_OFF, "Password:")], handler, false);
    assert_eq!(status, ffi::PAM_CONV_ERR);
    assert!(response.is_none());
    assert!(state.rejected());
}

#[test]
fn panic_after_secret_allocation_zeroizes_and_frees_partial_responses() {
    let handler = Arc::new(TestHandler::new([
        Reply::Secret(b"secret".to_vec()),
        Reply::Panic,
    ]));
    let messages = [
        message(ECHO_OFF, "Password:"),
        message(INFORMATION, "Checking account"),
    ];
    let (status, response, state) = invoke(&messages, handler, false);
    assert_eq!(status, ffi::PAM_CONV_ERR);
    assert!(response.is_none());
    assert!(state.panicked());
    assert_eq!(test_live_allocations(), 0);
}

#[test]
fn later_malformed_callback_latches_rejection_after_a_valid_prompt() {
    let handler = Arc::new(TestHandler::new([Reply::Secret(b"secret".to_vec())]));
    let (first_status, first_response, mut state) =
        invoke(&[message(ECHO_OFF, "Password:")], handler, false);
    assert_eq!(first_status, ffi::PAM_SUCCESS);
    drop(first_response);

    let (later_status, later_response) =
        test_invoke_conversation(&[message(99, "Malformed later message")], &mut state);
    assert_eq!(later_status, ffi::PAM_CONV_ERR);
    assert!(later_response.is_none());
    assert!(state.rejected());
    assert_eq!(
        test_require_successful_interaction(ffi::PAM_SUCCESS, ffi::PAM_SUCCESS, 1, true),
        Err(super::ReauthenticationError::InteractionRejected)
    );
    assert_eq!(test_live_allocations(), 0);
}

#[test]
fn overlong_or_invalid_utf8_messages_are_rejected() {
    let long = "x".repeat(1024);
    let invalid = CString::new([0xff_u8]).expect("non-NUL byte");
    for text in [CString::new(long).expect("no NUL"), invalid] {
        let handler = Arc::new(TestHandler::new([]));
        let (status, response, _) = invoke(&[(INFORMATION, text)], handler, false);
        assert_eq!(status, ffi::PAM_CONV_ERR);
        assert!(response.is_none());
    }
}
