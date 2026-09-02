use std::sync::Arc;

use block2::DynBlock;
use objc2::rc::Retained;
use objc2::runtime::{NSObject, ProtocolObject};
use objc2::{AnyThread, DefinedClass, define_class, extern_protocol, msg_send};
use objc2_foundation::{
    NSData, NSObjectProtocol, NSString, NSXPCConnection, NSXPCInterface, NSXPCListener,
    NSXPCListenerDelegate,
};

use super::{CredentialServiceRequestHandler, invoke_handler};
use crate::frame::{NativeReplyFrame, native as frame};
use crate::{CredentialServiceEndpointConfiguration, CredentialServiceEndpointRole};

extern_protocol!(
    /// Exact one-frame credential-service Objective-C protocol.
    ///
    /// # Safety
    ///
    /// Implementors must preserve the registered `NSData`/reply-block ABI.
    #[allow(clippy::missing_safety_doc)]
    #[name = "RunneCredentialServiceXpcProtocolV1"]
    unsafe trait CredentialServiceXpcProtocol: NSObjectProtocol {
        #[unsafe(method(exchange:reply:))]
        fn exchange_reply(&self, request: &NSData, reply: &DynBlock<dyn Fn(*mut NSData)>);
    }
);

struct ExportedObjectIvars {
    role: CredentialServiceEndpointRole,
    handler: Arc<dyn CredentialServiceRequestHandler>,
}

define_class!(
    #[unsafe(super = NSObject)]
    #[thread_kind = AnyThread]
    #[ivars = ExportedObjectIvars]
    struct ExportedObject;

    unsafe impl NSObjectProtocol for ExportedObject {}

    unsafe impl CredentialServiceXpcProtocol for ExportedObject {
        #[unsafe(method(exchange:reply:))]
        fn exchange_reply(&self, request: &NSData, reply: &DynBlock<dyn Fn(*mut NSData)>) {
            let result = frame::copy_request(request).and_then(|request| {
                invoke_handler(
                    self.ivars().handler.as_ref(),
                    self.ivars().role,
                    request.into_bytes(),
                )
                .and_then(NativeReplyFrame::new)
            });
            let data = result.map_or_else(|_| NSData::data(), |reply| frame::reply_data(&reply));
            reply.call((std::ptr::from_ref(&*data).cast_mut(),));
        }
    }
);

impl ExportedObject {
    fn new(
        role: CredentialServiceEndpointRole,
        handler: Arc<dyn CredentialServiceRequestHandler>,
    ) -> Retained<Self> {
        frame::protocol();
        let this = Self::alloc().set_ivars(ExportedObjectIvars { role, handler });
        // SAFETY: NSObject's init signature and the initialized ivars are valid.
        unsafe { msg_send![super(this), init] }
    }
}

struct ListenerDelegateIvars {
    object: Retained<ExportedObject>,
    interface: Retained<NSXPCInterface>,
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
            _listener: &NSXPCListener,
            connection: &NSXPCConnection,
        ) -> bool {
            connection.setExportedInterface(Some(&self.ivars().interface));
            // SAFETY: the retained object implements the interface's exact protocol.
            unsafe { connection.setExportedObject(Some(&self.ivars().object)) };
            connection.resume();
            true
        }
    }
);

impl ListenerDelegate {
    fn new(object: Retained<ExportedObject>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(ListenerDelegateIvars {
            object,
            interface: frame::interface(),
        });
        // SAFETY: NSObject's init signature and the initialized ivars are valid.
        unsafe { msg_send![super(this), init] }
    }
}

pub(super) struct NativeListener {
    listener: Retained<NSXPCListener>,
    _delegate: Retained<ListenerDelegate>,
}

impl NativeListener {
    pub(super) fn bind(
        configuration: &CredentialServiceEndpointConfiguration,
        handler: Arc<dyn CredentialServiceRequestHandler>,
    ) -> Self {
        let endpoint = NSString::from_str(configuration.endpoint_name());
        let requirement = NSString::from_str(configuration.client_requirement().as_str());
        let object = ExportedObject::new(configuration.role(), handler);
        let delegate = ListenerDelegate::new(object);
        let listener = NSXPCListener::initWithMachServiceName(NSXPCListener::alloc(), &endpoint);
        listener.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        listener.setConnectionCodeSigningRequirement(&requirement);
        listener.resume();
        Self {
            listener,
            _delegate: delegate,
        }
    }

    pub(super) fn invalidate(&self) {
        self.listener.invalidate();
    }
}

impl Drop for NativeListener {
    fn drop(&mut self) {
        self.listener.invalidate();
    }
}
