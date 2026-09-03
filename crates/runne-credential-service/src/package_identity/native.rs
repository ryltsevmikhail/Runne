#![allow(unsafe_code)]

use core::ffi::c_void;
use std::{os::unix::fs::PermissionsExt, path::Path};

use core_foundation::{
    base::{CFGetTypeID, TCFType},
    data::{CFData, CFDataGetTypeID},
    dictionary::{CFDictionary, CFDictionaryGetValue, CFDictionaryRef},
    string::{CFString, CFStringGetTypeID, CFStringRef},
    url::CFURL,
};
use security_framework::os::macos::code_signing::{Flags, SecStaticCode};
use security_framework_sys::code_signing::{SecStaticCodeCheckValidity, SecStaticCodeRef};

use super::ObservedIdentity;
use runne_macos_xpc::CredentialServiceXpcError;

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

pub(super) fn observe(path: &Path) -> Result<ObservedIdentity, CredentialServiceXpcError> {
    let code = validated_code(path)?;
    copy_identity(code.as_concrete_TypeRef())
}

#[cfg(feature = "test-support")]
pub(super) fn observe_local(path: &Path) -> Result<ObservedIdentity, CredentialServiceXpcError> {
    let code = validated_code(path)?;
    copy_local_identity(code.as_concrete_TypeRef())
}

fn validated_code(path: &Path) -> Result<SecStaticCode, CredentialServiceXpcError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| CredentialServiceXpcError::Unavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(CredentialServiceXpcError::Rejected);
    }
    let url = CFURL::from_path(path, false).ok_or(CredentialServiceXpcError::Rejected)?;
    let code = SecStaticCode::from_path(&url, Flags::NONE)
        .map_err(|_| CredentialServiceXpcError::Rejected)?;
    let flags = Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS;
    let status = unsafe {
        SecStaticCodeCheckValidity(
            code.as_concrete_TypeRef(),
            flags.bits(),
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(CredentialServiceXpcError::Rejected);
    }
    Ok(code)
}

fn copy_identity(code: SecStaticCodeRef) -> Result<ObservedIdentity, CredentialServiceXpcError> {
    let mut raw: CFDictionaryRef = std::ptr::null();
    let status = unsafe { SecCodeCopySigningInformation(code, SIGNING_INFORMATION, &raw mut raw) };
    if status != 0 || raw.is_null() {
        return Err(CredentialServiceXpcError::Rejected);
    }
    let information: CFDictionary = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    let identifier = copy_string(&information, unsafe { kSecCodeInfoIdentifier })?;
    let team_identifier = copy_string(&information, unsafe { kSecCodeInfoTeamIdentifier })?;
    let cdhash = copy_data(&information, unsafe { kSecCodeInfoUnique })?;
    Ok(ObservedIdentity {
        identifier,
        team_identifier,
        cdhash: cdhash
            .try_into()
            .map_err(|_| CredentialServiceXpcError::Rejected)?,
    })
}

#[cfg(feature = "test-support")]
fn copy_local_identity(
    code: SecStaticCodeRef,
) -> Result<ObservedIdentity, CredentialServiceXpcError> {
    let mut raw: CFDictionaryRef = std::ptr::null();
    let status = unsafe { SecCodeCopySigningInformation(code, SIGNING_INFORMATION, &raw mut raw) };
    if status != 0 || raw.is_null() {
        return Err(CredentialServiceXpcError::Rejected);
    }
    let information: CFDictionary = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    let identifier = copy_string(&information, unsafe { kSecCodeInfoIdentifier })?;
    let cdhash = copy_data(&information, unsafe { kSecCodeInfoUnique })?;
    Ok(ObservedIdentity {
        identifier,
        team_identifier: "LOCAL00000".into(),
        cdhash: cdhash
            .try_into()
            .map_err(|_| CredentialServiceXpcError::Rejected)?,
    })
}

fn value(
    information: &CFDictionary,
    key: CFStringRef,
) -> Result<*const c_void, CredentialServiceXpcError> {
    let value = unsafe { CFDictionaryGetValue(information.as_concrete_TypeRef(), key.cast()) };
    (!value.is_null())
        .then_some(value)
        .ok_or(CredentialServiceXpcError::Rejected)
}

fn copy_string(
    information: &CFDictionary,
    key: CFStringRef,
) -> Result<String, CredentialServiceXpcError> {
    let value = value(information, key)?;
    if unsafe { CFGetTypeID(value) } != unsafe { CFStringGetTypeID() } {
        return Err(CredentialServiceXpcError::Rejected);
    }
    Ok(unsafe { CFString::wrap_under_get_rule(value.cast_mut().cast()) }.to_string())
}

fn copy_data(
    information: &CFDictionary,
    key: CFStringRef,
) -> Result<Vec<u8>, CredentialServiceXpcError> {
    let value = value(information, key)?;
    if unsafe { CFGetTypeID(value) } != unsafe { CFDataGetTypeID() } {
        return Err(CredentialServiceXpcError::Rejected);
    }
    Ok(
        unsafe { CFData::wrap_under_get_rule(value.cast_mut().cast()) }
            .bytes()
            .to_vec(),
    )
}
