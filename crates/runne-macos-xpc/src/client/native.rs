use std::panic::AssertUnwindSafe;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Instant;

use block2::{ManualBlockEncoding, RcBlock};
use objc2::rc::Retained;
use objc2::{AnyThread, msg_send};
use objc2_foundation::{NSData, NSError, NSString, NSXPCConnection, NSXPCConnectionOptions};
use runne_platform_ports::credential_service::CredentialServiceCallContext;
use tokio::sync::{oneshot, watch};
use zeroize::Zeroizing;

use crate::frame::{NativeRequestFrame, native};
use crate::{CredentialServiceEndpointConfiguration, CredentialServiceXpcError};

pub mod call_state;

use call_state::{ConnectionInvalidator, NativeCallState, ReplyResult, UnknownTerminal};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionEvent {
    Active,
    Interrupted,
    Invalidated,
}

struct ReplyBlockEncoding;

// SAFETY: On 64-bit macOS this is the clang ABI encoding for
// `void (^)(NSData *)`, including the hidden block object at offset zero.
unsafe impl ManualBlockEncoding for ReplyBlockEncoding {
    type Arguments = (*mut NSData,);
    type Return = ();
    const ENCODING_CSTR: &'static core::ffi::CStr = c"v16@?0@8";
}

pub(super) struct NativeClient {
    connection: Arc<NativeConnection>,
    events: watch::Sender<ConnectionEvent>,
}

struct NativeConnection(Retained<NSXPCConnection>);

// SAFETY: Apple documents NSXPCConnection as thread-safe. Keeping the retained
// connection behind this private wrapper lets callback state hold only a Weak
// invalidator, avoiding a connection -> reply block -> connection retain cycle.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for NativeConnection {}
unsafe impl Sync for NativeConnection {}

impl ConnectionInvalidator for NativeConnection {
    fn invalidate(&self) {
        self.0.invalidate();
    }
}

// SAFETY: Apple documents NSXPCConnection as thread-safe. All callbacks carry
// only Send Rust state; Foundation objects are created and consumed in this module.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for NativeClient {}
// SAFETY: every mutating NSXPCConnection operation is internally synchronized.
unsafe impl Sync for NativeClient {}

impl NativeClient {
    pub(super) fn connect(
        configuration: &CredentialServiceEndpointConfiguration,
    ) -> Result<Self, CredentialServiceXpcError> {
        objc2::exception::catch(AssertUnwindSafe(|| Self::connect_native(configuration)))
            .map_err(|_| CredentialServiceXpcError::Rejected)
    }

    fn connect_native(configuration: &CredentialServiceEndpointConfiguration) -> Self {
        let endpoint = NSString::from_str(configuration.endpoint_name());
        let requirement = NSString::from_str(configuration.service_requirement().as_str());
        let connection = NSXPCConnection::initWithMachServiceName_options(
            NSXPCConnection::alloc(),
            &endpoint,
            NSXPCConnectionOptions(0),
        );
        connection.setRemoteObjectInterface(Some(&native::interface()));
        let (events, _) = watch::channel(ConnectionEvent::Active);
        let interrupted = events.clone();
        connection.setInterruptionHandler(Some(&RcBlock::new(move || {
            interrupted.send_replace(ConnectionEvent::Interrupted);
        })));
        let invalidated = events.clone();
        connection.setInvalidationHandler(Some(&RcBlock::new(move || {
            invalidated.send_replace(ConnectionEvent::Invalidated);
        })));
        connection.setCodeSigningRequirement(&requirement);
        connection.resume();
        Self {
            connection: Arc::new(NativeConnection(connection)),
            events,
        }
    }

    pub(super) async fn exchange(
        &self,
        bytes: Zeroizing<Vec<u8>>,
        context: CredentialServiceCallContext,
    ) -> ReplyResult {
        if context.cancellation().is_cancelled() {
            return Err(CredentialServiceXpcError::Cancelled);
        }
        if Instant::now() >= context.deadline() {
            return Err(CredentialServiceXpcError::TimedOut);
        }
        let mut events = self.events.subscribe();
        let connection_event = *events.borrow();
        match connection_event {
            ConnectionEvent::Active => {}
            ConnectionEvent::Interrupted => {
                return Err(CredentialServiceXpcError::Interrupted);
            }
            ConnectionEvent::Invalidated => {
                return Err(CredentialServiceXpcError::Invalidated);
            }
        }
        let request = NativeRequestFrame::new(bytes)?;
        let (mut receiver, call) = self.dispatch(request, &context)?;
        let timeout = tokio::time::sleep_until(context.deadline().into());
        tokio::pin!(timeout);
        tokio::select! {
            biased;
            () = &mut timeout => {
                call.close_unknown(UnknownTerminal::Timeout);
                Err(CredentialServiceXpcError::OutcomeUnknown)
            }
            () = context.cancellation().cancelled() => {
                call.close_unknown(UnknownTerminal::Cancelled);
                Err(CredentialServiceXpcError::OutcomeUnknown)
            }
            changed = events.changed() => {
                let terminal = match changed.map(|()| *events.borrow()) {
                    Ok(ConnectionEvent::Interrupted) => UnknownTerminal::Interrupted,
                    Ok(ConnectionEvent::Invalidated | ConnectionEvent::Active) | Err(_) => {
                        UnknownTerminal::Invalidated
                    }
                };
                call.close_unknown(terminal);
                Err(CredentialServiceXpcError::OutcomeUnknown)
            }
            result = &mut receiver => {
                let result = result.unwrap_or_else(|_| {
                    call.close_unknown(UnknownTerminal::ReceiverClosed);
                    Err(CredentialServiceXpcError::OutcomeUnknown)
                });
                if result.is_ok() {
                    call.accept_reply();
                }
                result
            },
        }
    }

    fn dispatch(
        &self,
        request: NativeRequestFrame,
        context: &CredentialServiceCallContext,
    ) -> Result<(oneshot::Receiver<ReplyResult>, NativeCallState), CredentialServiceXpcError> {
        if context.cancellation().is_cancelled() {
            return Err(CredentialServiceXpcError::Cancelled);
        }
        if Instant::now() >= context.deadline() {
            return Err(CredentialServiceXpcError::TimedOut);
        }
        // Foundation makes the sole Rust -> NSData request copy here. Rust owns
        // `request` in `call` until exactly one terminal transition.
        let data = native::request_data(&request);
        let (sender, receiver) = oneshot::channel();
        let invalidator: Arc<dyn ConnectionInvalidator> = self.connection.clone();
        let call = NativeCallState::new(request, sender, &invalidator);
        let error_reply = call.reply_handle();
        let error = RcBlock::new(move |_error: NonNull<NSError>| {
            error_reply.deliver_unknown(UnknownTerminal::DispatchError);
        });
        let proxy = self.connection.0.remoteObjectProxyWithErrorHandler(&error);
        let reply_handle = call.reply_handle();
        let reply =
            RcBlock::with_encoding::<_, _, _, ReplyBlockEncoding>(move |data: *mut NSData| {
                let Some(data) = NonNull::new(data) else {
                    reply_handle.deliver_unknown(UnknownTerminal::MalformedReply);
                    return;
                };
                match native::copy_reply(unsafe { data.as_ref() }) {
                    Ok(reply) => reply_handle.deliver(Ok(reply)),
                    Err(_) => reply_handle.deliver_unknown(UnknownTerminal::MalformedReply),
                }
            });
        if objc2::exception::catch(AssertUnwindSafe(|| {
            // SAFETY: proxy implements the registered one-NSData request/reply protocol.
            let _: () = unsafe { msg_send![&*proxy, exchange: &*data, reply: &*reply] };
        }))
        .is_err()
        {
            call.close_unknown(UnknownTerminal::DispatchError);
            return Err(CredentialServiceXpcError::OutcomeUnknown);
        }
        Ok((receiver, call))
    }
}

impl Drop for NativeClient {
    fn drop(&mut self) {
        self.connection.invalidate();
    }
}
