#![allow(unsafe_code)]

use core::ffi::c_void;

use core_foundation::base::{CFGetTypeID, TCFType};
use core_foundation::data::{CFData, CFDataGetTypeID};
use core_foundation::dictionary::{CFDictionary, CFDictionaryGetValue, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringGetTypeID, CFStringRef};
use security_framework::os::macos::code_signing::{Flags, SecCode, SecStaticCode};
use security_framework_sys::code_signing::{
    SecCodeCheckValidity, SecStaticCodeCheckValidity, SecStaticCodeRef,
};

use super::NativeSignedCodeIdentity;
use crate::MacOsPackagedWriterObservationError;

const SIGNING_INFORMATION: u32 = 1 << 1;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;

    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
}

pub(super) fn copy_static_identity(
    code: &SecStaticCode,
) -> Result<NativeSignedCodeIdentity, MacOsPackagedWriterObservationError> {
    check_requirement_free(code)?;
    copy_identity(code.as_concrete_TypeRef())
}

pub(super) fn copy_dynamic_identity(
    code: &SecCode,
) -> Result<NativeSignedCodeIdentity, MacOsPackagedWriterObservationError> {
    check_dynamic_requirement_free(code)?;
    copy_identity(code.as_concrete_TypeRef().cast())
}

fn check_requirement_free(code: &SecStaticCode) -> Result<(), MacOsPackagedWriterObservationError> {
    let flags = Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS;
    let status = unsafe {
        SecStaticCodeCheckValidity(
            code.as_concrete_TypeRef(),
            flags.bits(),
            std::ptr::null_mut(),
        )
    };
    (status == 0)
        .then_some(())
        .ok_or(MacOsPackagedWriterObservationError::Rejected)
}

fn check_dynamic_requirement_free(
    code: &SecCode,
) -> Result<(), MacOsPackagedWriterObservationError> {
    let flags = Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS;
    let status = unsafe {
        SecCodeCheckValidity(
            code.as_concrete_TypeRef(),
            flags.bits(),
            std::ptr::null_mut(),
        )
    };
    (status == 0)
        .then_some(())
        .ok_or(MacOsPackagedWriterObservationError::Rejected)
}

fn copy_identity(
    code: SecStaticCodeRef,
) -> Result<NativeSignedCodeIdentity, MacOsPackagedWriterObservationError> {
    let mut raw: CFDictionaryRef = std::ptr::null();
    let status = unsafe { SecCodeCopySigningInformation(code, SIGNING_INFORMATION, &raw mut raw) };
    if status != 0 || raw.is_null() {
        return Err(MacOsPackagedWriterObservationError::Rejected);
    }
    let information: CFDictionary = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    let identifier = copy_string(&information, unsafe { kSecCodeInfoIdentifier })?;
    let team_identifier = copy_string(&information, unsafe { kSecCodeInfoTeamIdentifier })?;
    let cdhash = copy_data(&information, unsafe { kSecCodeInfoUnique })?;
    NativeSignedCodeIdentity::from_parts(identifier, team_identifier, &cdhash)
}

fn value(
    information: &CFDictionary,
    key: CFStringRef,
) -> Result<*const c_void, MacOsPackagedWriterObservationError> {
    let value = unsafe { CFDictionaryGetValue(information.as_concrete_TypeRef(), key.cast()) };
    (!value.is_null())
        .then_some(value)
        .ok_or(MacOsPackagedWriterObservationError::Rejected)
}

fn copy_string(
    information: &CFDictionary,
    key: CFStringRef,
) -> Result<String, MacOsPackagedWriterObservationError> {
    let value = value(information, key)?;
    if unsafe { CFGetTypeID(value) } != unsafe { CFStringGetTypeID() } {
        return Err(MacOsPackagedWriterObservationError::Rejected);
    }
    let string = unsafe { CFString::wrap_under_get_rule(value.cast_mut().cast()) };
    Ok(string.to_string())
}

fn copy_data(
    information: &CFDictionary,
    key: CFStringRef,
) -> Result<Vec<u8>, MacOsPackagedWriterObservationError> {
    let value = value(information, key)?;
    if unsafe { CFGetTypeID(value) } != unsafe { CFDataGetTypeID() } {
        return Err(MacOsPackagedWriterObservationError::Rejected);
    }
    let data = unsafe { CFData::wrap_under_get_rule(value.cast_mut().cast()) };
    Ok(data.bytes().to_vec())
}
