#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::ptr::NonNull;

use objc2::rc::Retained;
use objc2::runtime::AnyProtocol;
use objc2_foundation::{NSData, NSXPCInterface};
use zeroize::Zeroizing;

use crate::CredentialServiceXpcError;
use crate::qualification_runner::{
    MAX_QUALIFICATION_RUNNER_FRAME_BYTES, QualificationRunnerSessionBinding,
    QualificationRunnerXpcError,
};

unsafe extern "C" {
    fn runne_qualification_runner_xpc_protocol_v1() -> *const AnyProtocol;
    fn runne_qualification_runner_current_login_session(
        effective_uid: *mut u32,
        audit_session: *mut i32,
    ) -> i32;
}

/// Returns the current non-root login session from kernel audit state.
///
/// This reads `auditinfo_addr_t.ai_asid` through `getaudit_addr`, rather than
/// `audit_session_self`, which returns a Mach port instead of an audit-session
/// identifier.
///
/// # Errors
///
/// Rejects root, a process outside a login session, or an unavailable kernel
/// audit record.
pub fn current_login_session_binding()
-> Result<QualificationRunnerSessionBinding, QualificationRunnerXpcError> {
    let mut effective_uid = 0_u32;
    let mut audit_session = 0_i32;
    // SAFETY: both output pointers are valid and refer to initialized local storage.
    let status = unsafe {
        runne_qualification_runner_current_login_session(
            std::ptr::addr_of_mut!(effective_uid),
            std::ptr::addr_of_mut!(audit_session),
        )
    };
    if status != 0 || effective_uid == 0 || audit_session <= 0 {
        return Err(QualificationRunnerXpcError::Rejected);
    }
    QualificationRunnerSessionBinding::new(effective_uid, audit_session)
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

#[cfg(test)]
mod tests {
    use super::current_login_session_binding;

    #[test]
    fn current_login_session_is_bound_to_the_kernel_euid_and_nonzero_audit_session() {
        let binding = current_login_session_binding();
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let effective_uid = unsafe { libc::geteuid() };
        if effective_uid == 0 {
            assert!(binding.is_err());
            return;
        }
        let binding = binding.expect("interactive macOS test process has a login audit session");
        assert_eq!(binding.expected_euid(), effective_uid);
        assert!(binding.expected_audit_session() > 0);
    }
}
