#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

use core_foundation::base::{CFGetTypeID, CFRelease, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionaryGetValue, CFDictionaryRef};
use core_foundation::string::CFStringRef;
use core_foundation::url::{CFURL, CFURLGetTypeID, CFURLRef};
use security_framework::os::macos::code_signing::{Flags, GuestAttributes, SecCode};
use security_framework_sys::code_signing::{
    SecCodeCheckValidity, SecStaticCodeRef, kSecCSNoNetworkAccess, kSecCSStrictValidate,
};

use super::super::{MacOsLocalPeerProcessIdentity, MacOsPackagedWriterObservationError};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoMainExecutable: CFStringRef;
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
}

pub(crate) struct NativeCodeObservation {
    code: SecCode,
    main_executable: PathBuf,
}

impl NativeCodeObservation {
    pub(crate) fn capture_self() -> Result<Self, MacOsPackagedWriterObservationError> {
        let code = SecCode::for_self(Flags::NONE)
            .map_err(|_| MacOsPackagedWriterObservationError::Unavailable)?;
        Self::capture(code)
    }

    pub(crate) fn capture_peer(
        peer: &MacOsLocalPeerProcessIdentity,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        Self::capture(peer.copy_guest_code()?)
    }

    fn capture(code: SecCode) -> Result<Self, MacOsPackagedWriterObservationError> {
        check_requirement_free_validity(&code)?;
        let main_executable = copy_main_executable(&code)?;
        Ok(Self {
            code,
            main_executable,
        })
    }

    pub(crate) fn revalidate(&self) -> Result<(), MacOsPackagedWriterObservationError> {
        check_requirement_free_validity(&self.code)?;
        (copy_main_executable(&self.code)? == self.main_executable)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)
    }

    pub(crate) fn matches_fresh(
        &self,
        fresh: &Self,
    ) -> Result<(), MacOsPackagedWriterObservationError> {
        self.revalidate()?;
        fresh.revalidate()?;
        (self.main_executable == fresh.main_executable)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)
    }

    pub(crate) fn main_executable(&self) -> &Path {
        &self.main_executable
    }

    pub(crate) const fn code(&self) -> &SecCode {
        &self.code
    }
}

fn check_requirement_free_validity(
    code: &SecCode,
) -> Result<(), MacOsPackagedWriterObservationError> {
    let flags = kSecCSStrictValidate | kSecCSNoNetworkAccess;
    let status =
        unsafe { SecCodeCheckValidity(code.as_concrete_TypeRef(), flags, std::ptr::null_mut()) };
    (status == 0)
        .then_some(())
        .ok_or(MacOsPackagedWriterObservationError::Rejected)
}

fn copy_main_executable(code: &SecCode) -> Result<PathBuf, MacOsPackagedWriterObservationError> {
    let mut information: CFDictionaryRef = std::ptr::null();
    let status = unsafe {
        SecCodeCopySigningInformation(code.as_concrete_TypeRef().cast(), 0, &raw mut information)
    };
    if status != 0 || information.is_null() {
        return Err(MacOsPackagedWriterObservationError::Rejected);
    }
    let result = unsafe {
        let value = CFDictionaryGetValue(information, kSecCodeInfoMainExecutable.cast());
        if value.is_null() || CFGetTypeID(value) != CFURLGetTypeID() {
            Err(MacOsPackagedWriterObservationError::Rejected)
        } else {
            let url = CFURL::wrap_under_get_rule(value.cast::<std::ffi::c_void>() as CFURLRef);
            url.to_path()
                .filter(|path| path.is_absolute())
                .ok_or(MacOsPackagedWriterObservationError::Rejected)
        }
    };
    unsafe { CFRelease(information.cast()) };
    result
}

pub(crate) fn guest_from_audit_token(
    token: &nix::sys::socket::audit_token_t,
) -> Result<SecCode, MacOsPackagedWriterObservationError> {
    let mut bytes = [0_u8; 32];
    for (chunk, value) in bytes.chunks_exact_mut(4).zip(token.val) {
        chunk.copy_from_slice(&value.to_ne_bytes());
    }
    let token = CFData::from_buffer(&bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(token.as_concrete_TypeRef());
    SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
}

#[cfg(test)]
pub(crate) fn test_only_guest_from_audit_token(
    token: &nix::sys::socket::audit_token_t,
) -> Result<SecCode, MacOsPackagedWriterObservationError> {
    guest_from_audit_token(token)
}
