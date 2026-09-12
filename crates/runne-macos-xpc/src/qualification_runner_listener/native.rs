use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use block2::{DynBlock, RcBlock};
use objc2::rc::Retained;
use objc2::runtime::{NSObject, ProtocolObject};
use objc2::{AnyThread, DefinedClass, define_class, extern_protocol, msg_send};
use objc2_foundation::{
    NSData, NSObjectProtocol, NSString, NSXPCConnection, NSXPCInterface, NSXPCListener,
    NSXPCListenerDelegate,
};

use super::{SessionSlot, start_session};
mod activity;
mod registry;
#[path = "timer.rs"]
mod timer;
use crate::qualification_runner::{
    QualificationRunnerEndpointConfiguration, QualificationRunnerPeer,
    QualificationRunnerSessionFactory, QualificationRunnerXpcError,
};
use crate::qualification_runner_native as frame;
use activity::{ConnectionActivity, ConnectionGuard};
use registry::AcceptedRegistry;

extern_protocol!(
    #[allow(clippy::missing_safety_doc)]
    #[name = "RunneQualificationRunnerXpcProtocolV1"]
    unsafe trait QualificationRunnerXpcProtocol: NSObjectProtocol {
        #[unsafe(method(exchange:reply:))]
        fn exchange_reply(&self, request: &NSData, reply: &DynBlock<dyn Fn(*mut NSData)>);
    }
);

struct ExportedObjectIvars {
    session: SessionSlot,
    guard: ConnectionGuard,
}

define_class!(
    #[unsafe(super = NSObject)]
    #[thread_kind = AnyThread]
    #[ivars = ExportedObjectIvars]
    struct ExportedObject;

    unsafe impl NSObjectProtocol for ExportedObject {}

    unsafe impl QualificationRunnerXpcProtocol for ExportedObject {
        #[unsafe(method(exchange:reply:))]
        fn exchange_reply(&self, request: &NSData, reply: &DynBlock<dyn Fn(*mut NSData)>) {
            let Some(_call) = self.ivars().guard.enter() else {
                self.close();
                if let Some(connection) = NSXPCConnection::currentConnection() {
                    connection.invalidate();
                }
                return;
            };
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                frame::copy_request(request)
                    .and_then(
                        crate::qualification_runner::QualificationRunnerRequest::from_zeroizing,
                    )
                    .and_then(|request| self.ivars().session.exchange(request))
            }))
            .unwrap_or(Err(QualificationRunnerXpcError::Unavailable));
            match result {
                Ok(reply_frame) if !self.ivars().session.is_closed() => {
                    let bytes = reply_frame.into_zeroizing();
                    let data = frame::reply_data(&bytes);
                    reply.call((std::ptr::from_ref(&*data).cast_mut(),));
                }
                _ => {
                    self.close();
                    if let Some(connection) = NSXPCConnection::currentConnection() {
                        connection.invalidate();
                    }
                }
            }
        }
    }
);

impl ExportedObject {
    fn new(session: SessionSlot, guard: ConnectionGuard) -> Retained<Self> {
        frame::protocol();
        let this = Self::alloc().set_ivars(ExportedObjectIvars { session, guard });
        // SAFETY: initialized ivars satisfy NSObject's init contract.
        unsafe { msg_send![super(this), init] }
    }

    fn close(&self) {
        self.ivars().session.close();
        self.ivars().guard.close();
    }
}

struct ListenerDelegateIvars {
    factory: Arc<dyn QualificationRunnerSessionFactory>,
    interface: Retained<NSXPCInterface>,
    endpoint: crate::QualificationRunnerEndpoint,
    expected_client: crate::qualification_runner::QualificationRunnerSessionBinding,
    activity: ConnectionActivity,
    accepted: AcceptedRegistry,
}

define_class!(
    #[unsafe(super = NSObject)]
    #[thread_kind = AnyThread]
    #[ivars = ListenerDelegateIvars]
    struct ListenerDelegate;

    unsafe impl NSObjectProtocol for ListenerDelegate {}

    unsafe impl NSXPCListenerDelegate for ListenerDelegate {
        #[unsafe(method(listener:shouldAcceptNewConnection:))]
        fn listener_should_accept_new_connection(
            &self,
            _: &NSXPCListener,
            connection: &NSXPCConnection,
        ) -> bool {
            let Some(guard) = self.ivars().activity.try_open() else {
                return false.into();
            };
            let binding = self.ivars().expected_client;
            let peer = QualificationRunnerPeer::new(
                connection.effectiveUserIdentifier(),
                audit_session_identifier(connection),
            );
            if peer.euid() != binding.expected_euid()
                || peer.audit_session() != binding.expected_audit_session()
            {
                guard.close();
                return false.into();
            }
            let Ok(session) =
                start_session(self.ivars().factory.as_ref(), self.ivars().endpoint, peer)
            else {
                guard.close();
                return false.into();
            };
            let object = ExportedObject::new(session, guard.clone());
            let slot = object.ivars().session.clone();
            let control = timer::ExpiryControl::new();
            if !self.ivars().accepted.insert(
                slot.clone(),
                guard.clone(),
                Arc::clone(&control),
                connection,
            ) {
                control.cancel();
                object.close();
                connection.invalidate();
                return false.into();
            }
            let interrupted = object.clone();
            let interrupted_control = Arc::clone(&control);
            connection.setInterruptionHandler(Some(&RcBlock::new(move || {
                interrupted_control.cancel();
                interrupted.close();
            })));
            let invalidated = object.clone();
            let invalidated_control = Arc::clone(&control);
            connection.setInvalidationHandler(Some(&RcBlock::new(move || {
                invalidated_control.cancel();
                invalidated.close();
            })));
            let Some(deadline) = object.ivars().session.deadline() else {
                guard.close();
                return false.into();
            };
            if !timer::schedule(connection, &slot, &guard, &control, deadline) {
                object.close();
                connection.invalidate();
                return false.into();
            }
            connection.setExportedInterface(Some(&self.ivars().interface));
            // SAFETY: this fresh object implements the interface's exact protocol.
            unsafe { connection.setExportedObject(Some(&object)) };
            connection.resume();
            true
        }
    }
);

impl ListenerDelegate {
    fn new(
        factory: Arc<dyn QualificationRunnerSessionFactory>,
        endpoint: crate::QualificationRunnerEndpoint,
        expected_client: crate::qualification_runner::QualificationRunnerSessionBinding,
    ) -> Retained<Self> {
        let this = Self::alloc().set_ivars(ListenerDelegateIvars {
            factory,
            interface: frame::interface(),
            endpoint,
            expected_client,
            activity: ConnectionActivity::new(),
            accepted: AcceptedRegistry::new(),
        });
        // SAFETY: initialized ivars satisfy NSObject's init contract.
        unsafe { msg_send![super(this), init] }
    }
}

pub(super) struct NativeQualificationRunnerListener {
    listener: Retained<NSXPCListener>,
    delegate: Retained<ListenerDelegate>,
}

impl NativeQualificationRunnerListener {
    pub(super) fn bind(
        configuration: &QualificationRunnerEndpointConfiguration,
        factory: Arc<dyn QualificationRunnerSessionFactory>,
    ) -> Result<Self, QualificationRunnerXpcError> {
        objc2::exception::catch(AssertUnwindSafe(|| {
            let endpoint = NSString::from_str(configuration.endpoint_name());
            let requirement = NSString::from_str(configuration.client_requirement().as_str());
            let delegate = ListenerDelegate::new(
                factory,
                configuration.endpoint(),
                configuration.expected_client(),
            );
            let listener =
                NSXPCListener::initWithMachServiceName(NSXPCListener::alloc(), &endpoint);
            listener.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
            listener.setConnectionCodeSigningRequirement(&requirement);
            listener.resume();
            Self { listener, delegate }
        }))
        .map_err(|_| QualificationRunnerXpcError::Rejected)
    }

    pub(super) fn invalidate(&self) {
        self.delegate.ivars().accepted.close_all();
        self.listener.invalidate();
    }
}

impl Drop for NativeQualificationRunnerListener {
    fn drop(&mut self) {
        self.delegate.ivars().accepted.close_all();
        self.listener.invalidate();
    }
}

fn audit_session_identifier(connection: &NSXPCConnection) -> i32 {
    unsafe extern "C" {
        fn runne_xpc_audit_session_identifier(connection: *const NSXPCConnection) -> i32;
    }
    // SAFETY: calls Foundation's public readonly property via the narrow C shim.
    unsafe { runne_xpc_audit_session_identifier(std::ptr::from_ref(connection)) }
}
