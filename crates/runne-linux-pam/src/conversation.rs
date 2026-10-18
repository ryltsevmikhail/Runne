#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;

use zeroize::{Zeroize, Zeroizing};

use crate::ffi::{self, PamMessage, PamResponse};
use crate::response_buffer::ResponseBuffer;
#[cfg(test)]
use crate::response_buffer::TestResponse;
use crate::types::{PamCancellation, PamInteractionError};
#[cfg(test)]
use std::ffi::CString;

const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
const MAX_MESSAGES: usize = 4;
const MAX_MESSAGE_BYTES: usize = 1024;
const MAX_SECRET_BYTES: usize = 4096;

/// A bounded PAM message style exposed to a native main-thread prompt bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PamMessageKind {
    EchoOff,
    Error,
    Information,
}

/// Synchronous UI bridge. Implementations may marshal to the existing native UI thread.
pub trait PamConversationHandler: Send + Sync + 'static {
    /// Presents one bounded PAM message and returns secret bytes only for `ECHO_OFF`.
    ///
    /// # Errors
    ///
    /// Returns an error when the native prompt is cancelled or rejects the request.
    fn present(
        &self,
        kind: PamMessageKind,
        message: &str,
        cancellation: &PamCancellation,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, PamInteractionError>;
}

pub struct ConversationState {
    handler: Arc<dyn PamConversationHandler>,
    cancellation: PamCancellation,
    deadline: Instant,
    echo_off_count: usize,
    cancelled: bool,
    rejected: bool,
    panicked: bool,
}

impl ConversationState {
    pub(super) fn new(
        handler: Arc<dyn PamConversationHandler>,
        cancellation: PamCancellation,
        deadline: Instant,
    ) -> Self {
        Self {
            handler,
            cancellation,
            deadline,
            echo_off_count: 0,
            cancelled: false,
            rejected: false,
            panicked: false,
        }
    }

    pub(super) const fn echo_off_count(&self) -> usize {
        self.echo_off_count
    }

    pub(super) const fn cancelled(&self) -> bool {
        self.cancelled
    }

    pub(super) const fn rejected(&self) -> bool {
        self.rejected
    }

    pub(super) const fn panicked(&self) -> bool {
        self.panicked
    }
}

/// C callback boundary: all Rust panics become `PAM_CONV_ERR`.
pub unsafe extern "C" fn pam_conversation(
    message_count: c_int,
    messages: *const *const PamMessage,
    response_out: *mut *mut PamResponse,
    app_data: *mut c_void,
) -> c_int {
    if response_out.is_null() {
        latch_failure(app_data, false);
        return ffi::PAM_CONV_ERR;
    }
    // SAFETY: `response_out` was checked non-null and is PAM's writable result slot.
    unsafe { *response_out = std::ptr::null_mut() };
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `app_data` is the live boxed state passed to pam_start.
        unsafe { converse(message_count, messages, response_out, app_data) }
    }));
    match result {
        Ok(Ok(())) => ffi::PAM_SUCCESS,
        Ok(Err(())) => {
            latch_failure(app_data, false);
            ffi::PAM_CONV_ERR
        }
        Err(_) => {
            latch_failure(app_data, true);
            ffi::PAM_CONV_ERR
        }
    }
}

fn latch_failure(app_data: *mut c_void, panicked: bool) {
    if !app_data.is_null() {
        // SAFETY: app_data is the live callback state installed by this transaction.
        unsafe {
            let state = &mut *app_data.cast::<ConversationState>();
            state.rejected = true;
            state.panicked |= panicked;
        }
    }
}

unsafe fn converse(
    message_count: c_int,
    messages: *const *const PamMessage,
    response_out: *mut *mut PamResponse,
    app_data: *mut c_void,
) -> Result<(), ()> {
    if app_data.is_null()
        || message_count <= 0
        || usize::try_from(message_count).map_err(|_| ())? > MAX_MESSAGES
        || messages.is_null()
    {
        return Err(());
    }
    // SAFETY: app_data was created from a live ConversationState for this PAM call.
    let state = unsafe { &mut *app_data.cast::<ConversationState>() };
    if state.cancellation.is_cancelled() {
        state.cancelled = true;
        return Err(());
    }
    if Instant::now() >= state.deadline {
        state.cancelled = true;
        return Err(());
    }
    let count = usize::try_from(message_count).map_err(|_| ())?;
    let mut responses = ResponseBuffer::new(count).ok_or(())?;
    for index in 0..count {
        // SAFETY: PAM supplied an array with `message_count` message pointers.
        let message = unsafe { *messages.add(index) };
        if message.is_null() {
            return Err(());
        }
        // SAFETY: the pointed-to PAM message remains live for this callback.
        let message = unsafe { &*message };
        let text = unsafe { bounded_message(message.msg) }.ok_or(())?;
        let kind = match message.msg_style {
            PAM_PROMPT_ECHO_OFF if state.echo_off_count == 0 => PamMessageKind::EchoOff,
            PAM_ERROR_MSG => PamMessageKind::Error,
            PAM_TEXT_INFO => PamMessageKind::Information,
            _ => return Err(()),
        };
        let presented = catch_unwind(AssertUnwindSafe(|| {
            state.handler.present(kind, &text, &state.cancellation)
        }));
        let presented = match presented {
            Ok(Ok(value)) => value,
            Ok(Err(PamInteractionError::Cancelled)) => {
                state.cancelled = true;
                return Err(());
            }
            Ok(Err(PamInteractionError::Rejected)) => {
                state.rejected = true;
                return Err(());
            }
            Err(_) => {
                state.panicked = true;
                return Err(());
            }
        };
        if state.cancellation.is_cancelled() || Instant::now() >= state.deadline {
            state.cancelled = true;
            return Err(());
        }
        match (kind, presented) {
            (PamMessageKind::EchoOff, Some(secret)) => {
                if secret.is_empty() || secret.len() > MAX_SECRET_BYTES || secret.contains(&0) {
                    state.rejected = true;
                    return Err(());
                }
                responses.set_secret(index, &secret)?;
                state.echo_off_count += 1;
            }
            (PamMessageKind::EchoOff, None) => {
                state.rejected = true;
                return Err(());
            }
            (PamMessageKind::Error | PamMessageKind::Information, None) => {}
            (PamMessageKind::Error | PamMessageKind::Information, Some(mut secret)) => {
                secret.zeroize();
                state.rejected = true;
                return Err(());
            }
        }
    }
    // SAFETY: PAM takes ownership of the malloc-compatible response array now.
    unsafe { *response_out = responses.transfer() };
    Ok(())
}

unsafe fn bounded_message(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let length = (0..MAX_MESSAGE_BYTES).find(|offset| {
        // SAFETY: PAM message is a C string owned for the callback duration.
        unsafe { *pointer.add(*offset) == 0 }
    })?;
    // SAFETY: the scan found a NUL within the bounded PAM message.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
    let message = std::str::from_utf8(bytes).ok()?;
    if message
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return None;
    }
    Some(message.to_owned())
}

#[cfg(test)]
pub fn test_invoke_conversation(
    messages: &[(c_int, CString)],
    state: &mut ConversationState,
) -> (c_int, Option<TestResponse>) {
    let message_rows: Vec<PamMessage> = messages
        .iter()
        .map(|(style, text)| PamMessage {
            msg_style: *style,
            msg: text.as_ptr(),
        })
        .collect();
    let message_pointers: Vec<*const PamMessage> =
        message_rows.iter().map(std::ptr::from_ref).collect();
    let mut response = std::ptr::null_mut();
    let status = unsafe {
        pam_conversation(
            c_int::try_from(message_pointers.len()).expect("bounded test input"),
            if message_pointers.is_empty() {
                std::ptr::null()
            } else {
                message_pointers.as_ptr()
            },
            &raw mut response,
            (&raw mut *state).cast::<c_void>(),
        )
    };
    let owned_response = if response.is_null() {
        None
    } else {
        // SAFETY: only this callback can populate the response output slot above.
        Some(unsafe { TestResponse::from_callback(response, message_pointers.len()) })
    };
    (status, owned_response)
}
