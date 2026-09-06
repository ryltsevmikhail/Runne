use std::panic::AssertUnwindSafe;
use std::ptr::NonNull;
use std::sync::Arc;

use block2::{ManualBlockEncoding, RcBlock};
use objc2::rc::Retained;
use objc2::{AnyThread, msg_send};
use objc2_foundation::{NSData, NSError, NSString, NSXPCConnection, NSXPCConnectionOptions};
use runne_platform_ports::credential_service::CredentialServiceCallContext;
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::frame::{NativeRequestFrame, native};
use crate::{CredentialServiceEndpointConfiguration, CredentialServiceXpcError};

pub mod call_state;
pub mod exchange;

use call_state::{ConnectionInvalidator, ReplyResult};
use exchange::{ConnectionEvent, ExchangeConnection, NativeCallbacks};

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
}

struct NativeConnection {
    object: Retained<NSXPCConnection>,
    events: watch::Sender<ConnectionEvent>,
}

// SAFETY: Apple documents NSXPCConnection as thread-safe. Keeping the retained
// connection behind this private wrapper lets callback state hold only a Weak
// invalidator, avoiding a connection -> reply block -> connection retain cycle.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for NativeConnection {}
unsafe impl Sync for NativeConnection {}

impl ConnectionInvalidator for NativeConnection {
    fn invalidate(&self) {
        self.object.invalidate();
    }
}

impl ExchangeConnection for NativeConnection {
    type PreparedRequest = Retained<NSData>;

    fn subscribe(&self) -> watch::Receiver<ConnectionEvent> {
        self.events.subscribe()
    }

    fn prepare(&self, request: &NativeRequestFrame) -> Self::PreparedRequest {
        // Foundation makes the sole Rust -> NSData request copy here.
        native::request_data(request)
    }

    fn dispatch(&self, data: Self::PreparedRequest, callbacks: NativeCallbacks) -> Result<(), ()> {
        let error_callbacks = callbacks.clone();
        let error = RcBlock::new(move |_error: NonNull<NSError>| {
            error_callbacks.proxy_error();
        });
        let proxy = self.object.remoteObjectProxyWithErrorHandler(&error);
        let reply =
            RcBlock::with_encoding::<_, _, _, ReplyBlockEncoding>(move |data: *mut NSData| {
                let Some(data) = NonNull::new(data) else {
                    callbacks.native_reply(Err(CredentialServiceXpcError::InvalidReply));
                    return;
                };
                callbacks.native_reply(native::copy_reply(unsafe { data.as_ref() }));
            });
        objc2::exception::catch(AssertUnwindSafe(|| {
            // SAFETY: proxy implements the registered one-NSData request/reply protocol.
            let _: () = unsafe { msg_send![&*proxy, exchange: &*data, reply: &*reply] };
        }))
        .map_err(|_| ())
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
            connection: Arc::new(NativeConnection {
                object: connection,
                events,
            }),
        }
    }

    pub(super) async fn exchange(
        &self,
        bytes: Zeroizing<Vec<u8>>,
        context: CredentialServiceCallContext,
    ) -> ReplyResult {
        exchange::exchange(Arc::clone(&self.connection), bytes, context).await
    }
}

impl Drop for NativeClient {
    fn drop(&mut self) {
        self.connection.invalidate();
    }
}
