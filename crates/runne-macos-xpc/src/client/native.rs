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

use crate::{CredentialServiceEndpointConfiguration, CredentialServiceXpcError};
mod domain;
use domain::NativeXpcDomain;

#[derive(Clone, Copy)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct NativePeerBinding {
    pub(crate) expected_euid: u32,
    pub(crate) expected_audit_session: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionEvent {
    Active,
    Interrupted,
    Invalidated,
}

type ReplyResult = Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError>;
type ReplySlot = Arc<Mutex<Option<oneshot::Sender<ReplyResult>>>>;

struct ReplyBlockEncoding;

// SAFETY: On 64-bit macOS this is the clang ABI encoding for
// `void (^)(NSData *)`, including the hidden block object at offset zero.
unsafe impl ManualBlockEncoding for ReplyBlockEncoding {
    type Arguments = (*mut NSData,);
    type Return = ();
    const ENCODING_CSTR: &'static core::ffi::CStr = c"v16@?0@8";
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) struct NativeClient {
    connection: Retained<NSXPCConnection>,
    events: watch::Sender<ConnectionEvent>,
    domain: NativeXpcDomain,
    peer_binding: Option<NativePeerBinding>,
}

// SAFETY: Apple documents NSXPCConnection as thread-safe. All callbacks carry
// only Send Rust state; Foundation objects are created and consumed in this module.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for NativeClient {}
// SAFETY: every mutating NSXPCConnection operation is internally synchronized.
unsafe impl Sync for NativeClient {}

#[derive(Clone, Copy)]
enum NativeConnectionTarget {
    Credential(&'static str),
    Qualification(crate::QualificationRunnerEndpoint),
}

impl NativeConnectionTarget {
    const fn endpoint_name(self) -> &'static str {
        match self {
            Self::Credential(endpoint) => endpoint,
            Self::Qualification(endpoint) => endpoint.mach_service_name(),
        }
    }

    const fn domain(self) -> NativeXpcDomain {
        match self {
            Self::Credential(_) => NativeXpcDomain::Credential,
            Self::Qualification(_) => NativeXpcDomain::Qualification,
        }
    }

    const fn options(self) -> NSXPCConnectionOptions {
        match self {
            Self::Credential(_)
            | Self::Qualification(
                crate::QualificationRunnerEndpoint::DesktopBootstrap
                | crate::QualificationRunnerEndpoint::RuntimeBootstrap,
            ) => NSXPCConnectionOptions(0),
            Self::Qualification(crate::QualificationRunnerEndpoint::RootConsume) => {
                NSXPCConnectionOptions::Privileged
            }
        }
    }
}

impl NativeClient {
    pub(crate) fn connect(
        configuration: &CredentialServiceEndpointConfiguration,
    ) -> Result<Self, CredentialServiceXpcError> {
        objc2::exception::catch(AssertUnwindSafe(|| Self::connect_native(configuration)))
            .map_err(|_| CredentialServiceXpcError::Rejected)
    }

    fn connect_native(configuration: &CredentialServiceEndpointConfiguration) -> Self {
        Self::connect_closed(
            NativeConnectionTarget::Credential(configuration.endpoint_name()),
            configuration.service_requirement().as_str(),
            None,
        )
    }

    pub(crate) fn connect_qualification(
        endpoint: crate::QualificationRunnerEndpoint,
        service_requirement: &str,
        peer_binding: NativePeerBinding,
    ) -> Result<Self, CredentialServiceXpcError> {
        objc2::exception::catch(AssertUnwindSafe(|| {
            Self::connect_closed(
                NativeConnectionTarget::Qualification(endpoint),
                service_requirement,
                Some(peer_binding),
            )
        }))
        .map_err(|_| CredentialServiceXpcError::Rejected)
    }

    fn connect_closed(
        target: NativeConnectionTarget,
        service_requirement: &str,
        peer_binding: Option<NativePeerBinding>,
    ) -> Self {
        let endpoint = NSString::from_str(target.endpoint_name());
        let requirement = NSString::from_str(service_requirement);
        let connection = NSXPCConnection::initWithMachServiceName_options(
            NSXPCConnection::alloc(),
            &endpoint,
            target.options(),
        );
        connection.setRemoteObjectInterface(Some(&target.domain().interface()));
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
            connection,
            events,
            domain: target.domain(),
            peer_binding,
        }
    }

    pub(crate) async fn exchange(
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
        let request = self.domain.prepare_request(bytes)?;
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
        request: &Zeroizing<Vec<u8>>,
        context: &CredentialServiceCallContext,
    ) -> Result<(oneshot::Receiver<ReplyResult>, ReplySlot), CredentialServiceXpcError> {
        if context.cancellation().is_cancelled() {
            return Err(CredentialServiceXpcError::Cancelled);
        }
        if Instant::now() >= context.deadline() {
            return Err(CredentialServiceXpcError::TimedOut);
        }
        let data = self.domain.request_data(request);
        let (sender, receiver) = oneshot::channel();
        let slot = Arc::new(Mutex::new(Some(sender)));
        let error_slot = Arc::clone(&slot);
        let error = RcBlock::new(move |_error: NonNull<NSError>| {
            send_once(&error_slot, Err(CredentialServiceXpcError::OutcomeUnknown));
        });
        let proxy = self.connection.remoteObjectProxyWithErrorHandler(&error);
        let reply_slot = Arc::clone(&slot);
        let reply_connection = self.connection.clone();
        let peer_binding = self.peer_binding;
        let domain = self.domain;
        let reply =
            RcBlock::with_encoding::<_, _, _, ReplyBlockEncoding>(move |data: *mut NSData| {
                let result = NonNull::new(data)
                    .ok_or(CredentialServiceXpcError::OutcomeUnknown)
                    .and_then(|data| {
                        if peer_binding.is_some_and(|binding| {
                            assert_peer_binding(&reply_connection, binding).is_err()
                        }) {
                            Err(CredentialServiceXpcError::OutcomeUnknown)
                        } else {
                            domain.copy_reply(unsafe { data.as_ref() })
                        }
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

impl NativeClient {
    pub(crate) fn invalidate(&self) {
        self.connection.invalidate();
    }
}

fn assert_peer_binding(
    connection: &NSXPCConnection,
    binding: NativePeerBinding,
) -> Result<(), CredentialServiceXpcError> {
    if connection.effectiveUserIdentifier() != binding.expected_euid
        || audit_session_identifier(connection) != binding.expected_audit_session
    {
        connection.invalidate();
        return Err(CredentialServiceXpcError::Rejected);
    }
    Ok(())
}

fn audit_session_identifier(connection: &NSXPCConnection) -> i32 {
    unsafe extern "C" {
        fn runne_xpc_audit_session_identifier(connection: *const NSXPCConnection) -> i32;
    }
    // SAFETY: the shim invokes Foundation's public readonly property on a live connection.
    unsafe { runne_xpc_audit_session_identifier(std::ptr::from_ref(connection)) }
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
