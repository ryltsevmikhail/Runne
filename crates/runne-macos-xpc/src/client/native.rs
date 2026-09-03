use std::panic::AssertUnwindSafe;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use block2::{ManualBlockEncoding, RcBlock};
use objc2::rc::Retained;
use objc2::{AnyThread, msg_send};
use objc2_foundation::{NSData, NSError, NSString, NSXPCConnection, NSXPCConnectionOptions};
use runne_platform_ports::credential_service::CredentialServiceCallContext;
use tokio::sync::{oneshot, watch};
use zeroize::Zeroizing;

use crate::frame::{NativeReplyFrame, NativeRequestFrame, native};
use crate::{CredentialServiceEndpointConfiguration, CredentialServiceXpcError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionEvent {
    Active,
    Interrupted,
    Invalidated,
}

type ReplyResult = Result<NativeReplyFrame, CredentialServiceXpcError>;
type ReplySlot = Arc<Mutex<Option<oneshot::Sender<ReplyResult>>>>;

struct ReplyBlockEncoding;

// SAFETY: On 64-bit macOS this is the clang ABI encoding for
// `void (^)(NSData *)`, including the hidden block object at offset zero.
unsafe impl ManualBlockEncoding for ReplyBlockEncoding {
    type Arguments = (*mut NSData,);
    type Return = ();
    const ENCODING_CSTR: &'static core::ffi::CStr = c"v16@?0@8";
}

pub(super) struct NativeClient {
    connection: Retained<NSXPCConnection>,
    events: watch::Sender<ConnectionEvent>,
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
        Self { connection, events }
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
        let (mut receiver, slot) = self.dispatch(&request, &context)?;
        let timeout = tokio::time::sleep_until(context.deadline().into());
        tokio::pin!(timeout);
        tokio::select! {
            biased;
            () = &mut timeout => {
                close_slot(&slot);
                Err(CredentialServiceXpcError::OutcomeUnknown)
            }
            () = context.cancellation().cancelled() => {
                close_slot(&slot);
                Err(CredentialServiceXpcError::OutcomeUnknown)
            }
            changed = events.changed() => {
                close_slot(&slot);
                match changed.map(|()| *events.borrow()) {
                    Ok(ConnectionEvent::Interrupted | ConnectionEvent::Invalidated | ConnectionEvent::Active) | Err(_) => {
                        Err(CredentialServiceXpcError::OutcomeUnknown)
                    }
                }
            }
            result = &mut receiver => result.unwrap_or(Err(CredentialServiceXpcError::OutcomeUnknown)),
        }
    }

    fn dispatch(
        &self,
        request: &NativeRequestFrame,
        context: &CredentialServiceCallContext,
    ) -> Result<(oneshot::Receiver<ReplyResult>, ReplySlot), CredentialServiceXpcError> {
        if context.cancellation().is_cancelled() {
            return Err(CredentialServiceXpcError::Cancelled);
        }
        if Instant::now() >= context.deadline() {
            return Err(CredentialServiceXpcError::TimedOut);
        }
        let data = native::request_data(request);
        let (sender, receiver) = oneshot::channel();
        let slot = Arc::new(Mutex::new(Some(sender)));
        let error_slot = Arc::clone(&slot);
        let error = RcBlock::new(move |_error: NonNull<NSError>| {
            send_once(&error_slot, Err(CredentialServiceXpcError::OutcomeUnknown));
        });
        let proxy = self.connection.remoteObjectProxyWithErrorHandler(&error);
        let reply_slot = Arc::clone(&slot);
        let reply =
            RcBlock::with_encoding::<_, _, _, ReplyBlockEncoding>(move |data: *mut NSData| {
                let result = NonNull::new(data)
                    .ok_or(CredentialServiceXpcError::OutcomeUnknown)
                    .and_then(|data| {
                        native::copy_reply(unsafe { data.as_ref() })
                            .map_err(|_| CredentialServiceXpcError::OutcomeUnknown)
                    });
                send_once(&reply_slot, result);
            });
        objc2::exception::catch(AssertUnwindSafe(|| {
            // SAFETY: proxy implements the registered one-NSData request/reply protocol.
            let _: () = unsafe { msg_send![&*proxy, exchange: &*data, reply: &*reply] };
        }))
        .map_err(|_| CredentialServiceXpcError::OutcomeUnknown)?;
        Ok((receiver, slot))
    }
}

impl Drop for NativeClient {
    fn drop(&mut self) {
        self.connection.invalidate();
    }
}

fn send_once(slot: &ReplySlot, result: ReplyResult) {
    let sender = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(sender) = sender {
        let _ = sender.send(result);
    }
}

fn close_slot(slot: &ReplySlot) {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
}
