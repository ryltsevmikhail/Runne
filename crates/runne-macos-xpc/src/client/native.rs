use std::panic::AssertUnwindSafe;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Instant;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::{AnyThread, msg_send};
use objc2_foundation::{NSData, NSError, NSString, NSXPCConnection, NSXPCConnectionOptions};
use runne_platform_ports::credential_service::CredentialServiceCallContext;
use tokio::sync::{oneshot, watch};
use zeroize::Zeroizing;

use crate::{CredentialServiceEndpointConfiguration, CredentialServiceXpcError};
mod domain;
use domain::NativeXpcDomain;
mod revalidation;
use revalidation::{
    ConnectionEvent, PeerObservation, ReplyBlockEncoding, ReplyResult, ReplySlot, close_slot,
    new_reply_slot, send_once,
};

#[derive(Clone, Copy)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct NativePeerBinding {
    pub(crate) expected_euid: u32,
    pub(crate) expected_audit_session: i32,
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) struct NativeClient {
    connection: Retained<NSXPCConnection>,
    events: watch::Sender<ConnectionEvent>,
    domain: NativeXpcDomain,
    peer_binding: Option<NativePeerBinding>,
    observation: Arc<PeerObservation>,
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
        let observation = Arc::new(PeerObservation::new());
        let qualification_connection = peer_binding.is_some();
        let interrupted = events.clone();
        let interrupted_observation = Arc::clone(&observation);
        connection.setInterruptionHandler(Some(&RcBlock::new(move || {
            if qualification_connection {
                interrupted_observation.mark_terminal();
            }
            interrupted.send_replace(ConnectionEvent::Interrupted);
        })));
        let invalidated = events.clone();
        let invalidated_observation = Arc::clone(&observation);
        connection.setInvalidationHandler(Some(&RcBlock::new(move || {
            if qualification_connection {
                invalidated_observation.mark_terminal();
            }
            invalidated.send_replace(ConnectionEvent::Invalidated);
        })));
        connection.setCodeSigningRequirement(&requirement);
        connection.resume();
        Self {
            connection,
            events,
            domain: target.domain(),
            peer_binding,
            observation,
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
        let (receiver, slot) = new_reply_slot();
        let error_slot = Arc::clone(&slot);
        let error_observation = Arc::clone(&self.observation);
        let error_connection = self.connection.clone();
        let qualification_connection = self.peer_binding.is_some();
        let error = RcBlock::new(move |_error: NonNull<NSError>| {
            if qualification_connection {
                error_observation.mark_terminal();
                error_connection.invalidate();
            }
            send_once(&error_slot, Err(CredentialServiceXpcError::OutcomeUnknown));
        });
        let proxy = self.connection.remoteObjectProxyWithErrorHandler(&error);
        let reply_slot = Arc::clone(&slot);
        let reply_connection = self.connection.clone();
        let peer_binding = self.peer_binding;
        let reply_observation = Arc::clone(&self.observation);
        let domain = self.domain;
        let reply =
            RcBlock::with_encoding::<_, _, _, ReplyBlockEncoding>(move |data: *mut NSData| {
                let result = NonNull::new(data)
                    .ok_or(CredentialServiceXpcError::OutcomeUnknown)
                    .and_then(|data| {
                        if let Some(binding) = peer_binding {
                            revalidation::assert_peer_binding(&reply_connection, binding)
                                .map_err(|_| CredentialServiceXpcError::OutcomeUnknown)?;
                        }
                        domain.copy_reply(unsafe { data.as_ref() })
                    });
                if peer_binding.is_some() {
                    if result.is_ok() {
                        reply_observation.observe_verified_reply();
                    } else {
                        reply_observation.mark_terminal();
                        reply_connection.invalidate();
                    }
                }
                send_once(&reply_slot, result);
            });
        if objc2::exception::catch(AssertUnwindSafe(|| {
            // SAFETY: proxy implements the registered one-NSData request/reply protocol.
            let _: () = unsafe { msg_send![&*proxy, exchange: &*data, reply: &*reply] };
        }))
        .is_err()
        {
            if self.peer_binding.is_some() {
                self.observation.mark_terminal();
                self.connection.invalidate();
            }
            return Err(CredentialServiceXpcError::OutcomeUnknown);
        }
        Ok((receiver, slot))
    }

    pub(crate) fn invalidate(&self) {
        if self.peer_binding.is_some() {
            self.observation.mark_terminal();
        }
        self.connection.invalidate();
    }
}

impl Drop for NativeClient {
    fn drop(&mut self) {
        if self.peer_binding.is_some() {
            self.observation.mark_terminal();
        }
        self.connection.invalidate();
    }
}
