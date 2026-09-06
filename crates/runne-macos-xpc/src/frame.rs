#![allow(clippy::redundant_pub_crate)]

use runne_platform_ports::credential_service::MAX_CREDENTIAL_SERVICE_FRAME_BYTES;
use zeroize::Zeroizing;

use crate::CredentialServiceXpcError;

#[cfg(test)]
pub(crate) struct FrameDropWitness(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl FrameDropWitness {
    pub(crate) fn new(count: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
        Self(count)
    }

    fn record(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
}

macro_rules! native_frame {
    ($name:ident) => {
        pub(crate) struct $name {
            bytes: Option<Zeroizing<Vec<u8>>>,
            #[cfg(test)]
            drop_witness: Option<FrameDropWitness>,
        }

        impl $name {
            pub(crate) fn new(
                bytes: Zeroizing<Vec<u8>>,
            ) -> Result<Self, CredentialServiceXpcError> {
                if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_SERVICE_FRAME_BYTES {
                    return Err(CredentialServiceXpcError::Rejected);
                }
                Ok(Self {
                    bytes: Some(bytes),
                    #[cfg(test)]
                    drop_witness: None,
                })
            }

            #[cfg(test)]
            pub(crate) fn new_observed(
                bytes: Zeroizing<Vec<u8>>,
                drop_witness: FrameDropWitness,
            ) -> Result<Self, CredentialServiceXpcError> {
                Self::new(bytes).map(|mut frame| {
                    frame.drop_witness = Some(drop_witness);
                    frame
                })
            }

            pub(crate) fn with_bytes<T>(&self, use_bytes: impl FnOnce(&[u8]) -> T) -> T {
                use_bytes(self.bytes.as_deref().expect("native frame bytes are owned"))
            }

            pub(crate) fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
                self.bytes.take().expect("native frame bytes are owned")
            }
        }

        #[cfg(test)]
        impl Drop for $name {
            fn drop(&mut self) {
                if let Some(witness) = &self.drop_witness {
                    witness.record();
                }
            }
        }
    };
}

native_frame!(NativeRequestFrame);
native_frame!(NativeReplyFrame);

#[cfg(target_os = "macos")]
pub(crate) mod native {
    use objc2::rc::Retained;
    use objc2::runtime::AnyProtocol;
    use objc2_foundation::{NSData, NSXPCInterface};
    use std::ffi::c_void;
    use std::ptr::NonNull;
    use zeroize::Zeroizing;

    use super::{NativeReplyFrame, NativeRequestFrame};
    use crate::CredentialServiceXpcError;

    unsafe extern "C" {
        fn runne_credential_service_xpc_protocol_v1() -> *const AnyProtocol;
    }

    pub(crate) fn interface() -> Retained<NSXPCInterface> {
        let protocol = protocol();
        // SAFETY: the registered protocol has exactly one NSData request/reply method.
        unsafe { NSXPCInterface::interfaceWithProtocol(protocol) }
    }

    pub(crate) fn protocol() -> &'static AnyProtocol {
        // SAFETY: the Clang-compiled translation unit returns its static protocol.
        let protocol = unsafe { runne_credential_service_xpc_protocol_v1() };
        // SAFETY: Objective-C protocol metadata has process lifetime.
        unsafe { protocol.as_ref() }.expect("credential XPC protocol must be linked")
    }

    /// Makes the sole bounded request copy into Foundation-owned storage.
    /// Repository code cannot claim that `NSData` storage is wiped on release.
    pub(crate) fn request_data(frame: &NativeRequestFrame) -> Retained<NSData> {
        frame.with_bytes(|bytes| {
            // SAFETY: NSData copies the valid borrowed bytes before this call returns.
            unsafe { NSData::dataWithBytes_length(bytes.as_ptr().cast::<c_void>(), bytes.len()) }
        })
    }

    /// Makes the sole bounded reply copy into Foundation-owned storage.
    /// Repository code cannot claim that `NSData` storage is wiped on release.
    pub(crate) fn reply_data(frame: &NativeReplyFrame) -> Retained<NSData> {
        frame.with_bytes(|bytes| {
            // SAFETY: NSData copies the valid borrowed bytes before this call returns.
            unsafe { NSData::dataWithBytes_length(bytes.as_ptr().cast::<c_void>(), bytes.len()) }
        })
    }

    pub(crate) fn copy_reply(data: &NSData) -> Result<NativeReplyFrame, CredentialServiceXpcError> {
        let length = data.length();
        if length == 0
            || length > runne_platform_ports::credential_service::MAX_CREDENTIAL_SERVICE_FRAME_BYTES
        {
            return Err(CredentialServiceXpcError::InvalidReply);
        }
        let mut bytes = Zeroizing::new(vec![0_u8; length]);
        let destination = NonNull::new(bytes.as_mut_ptr().cast::<c_void>())
            .ok_or(CredentialServiceXpcError::InvalidReply)?;
        // SAFETY: destination is writable for exactly `length` bytes.
        unsafe { data.getBytes_length(destination, length) };
        NativeReplyFrame::new(bytes).map_err(|_| CredentialServiceXpcError::InvalidReply)
    }

    pub(crate) fn copy_request(
        data: &NSData,
    ) -> Result<NativeRequestFrame, CredentialServiceXpcError> {
        let length = data.length();
        if length == 0
            || length > runne_platform_ports::credential_service::MAX_CREDENTIAL_SERVICE_FRAME_BYTES
        {
            return Err(CredentialServiceXpcError::Rejected);
        }
        let mut bytes = Zeroizing::new(vec![0_u8; length]);
        let destination = NonNull::new(bytes.as_mut_ptr().cast::<c_void>())
            .ok_or(CredentialServiceXpcError::Rejected)?;
        // SAFETY: destination is writable for exactly `length` bytes.
        unsafe { data.getBytes_length(destination, length) };
        NativeRequestFrame::new(bytes)
    }
}
