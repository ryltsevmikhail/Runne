#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::ptr::NonNull;

use objc2::rc::Retained;
use objc2::runtime::AnyProtocol;
use objc2_foundation::{NSData, NSXPCInterface};
use zeroize::Zeroizing;

use crate::CredentialServiceXpcError;
use crate::qualification_runner::{
    MAX_QUALIFICATION_RUNNER_FRAME_BYTES, QualificationRunnerXpcError,
};

unsafe extern "C" {
    fn runne_qualification_runner_xpc_protocol_v1() -> *const AnyProtocol;
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn interface() -> Retained<NSXPCInterface> {
    // SAFETY: the C translation unit returns static protocol metadata.
    unsafe { NSXPCInterface::interfaceWithProtocol(protocol()) }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn protocol() -> &'static AnyProtocol {
    // SAFETY: Objective-C protocol metadata has process lifetime.
    unsafe { runne_qualification_runner_xpc_protocol_v1().as_ref() }
        .expect("qualification XPC protocol must be linked")
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn request_data(bytes: &[u8]) -> Retained<NSData> {
    // SAFETY: NSData copies the borrowed bytes before this call returns.
    unsafe { NSData::dataWithBytes_length(bytes.as_ptr().cast::<c_void>(), bytes.len()) }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn reply_data(bytes: &[u8]) -> Retained<NSData> {
    request_data(bytes)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn copy_request(
    data: &NSData,
) -> Result<Zeroizing<Vec<u8>>, QualificationRunnerXpcError> {
    copy_bytes(data).map_err(|()| QualificationRunnerXpcError::Rejected)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn copy_reply(data: &NSData) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
    copy_bytes(data).map_err(|()| CredentialServiceXpcError::InvalidReply)
}

fn copy_bytes(data: &NSData) -> Result<Zeroizing<Vec<u8>>, ()> {
    let length = data.length();
    if length == 0 || length > MAX_QUALIFICATION_RUNNER_FRAME_BYTES {
        return Err(());
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    let destination = NonNull::new(bytes.as_mut_ptr().cast::<c_void>()).ok_or(())?;
    // SAFETY: destination is writable for exactly `length` bytes.
    unsafe { data.getBytes_length(destination, length) };
    Ok(bytes)
}
