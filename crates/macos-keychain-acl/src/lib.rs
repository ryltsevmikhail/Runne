//! Narrow safe wrapper for legacy macOS Keychain executable ACL APIs.
//!
//! The rest of the workspace forbids unsafe code. This crate contains the
//! minimum auditable FFI required to create and verify a generic-password
//! decrypt ACL. It never receives credential bytes.

#![cfg(target_os = "macos")]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;

use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::{CFType, CFTypeRef, OSStatus, TCFType as _};
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::string::{CFString, CFStringRef};
use security_framework::os::macos::access::SecAccess;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::keychain_item::SecKeychainItem;
use security_framework_sys::base::{
    SecAccessRef, SecKeychainAttribute, SecKeychainAttributeList, SecKeychainItemRef,
    errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecSuccess,
};
use security_framework_sys::keychain_item::SecKeychainItemDelete;
use sha2::{Digest as _, Sha256};

const ACL_DESCRIPTOR: &str = "GOCODE provider credential";
const PROMPT_REQUIRE_PASSPHRASE: u16 = 0x0001;
const ERR_SEC_INTERACTION_NOT_ALLOWED: OSStatus = -25_308;
const ERR_SEC_NO_ACCESS_FOR_ITEM: OSStatus = -25_243;
const ERR_SEC_INVALID_OWNER_EDIT: OSStatus = -25_244;
const GENERIC_PASSWORD_ITEM_CLASS: u32 = u32::from_be_bytes(*b"genp");
const ACCOUNT_ITEM_ATTRIBUTE: u32 = u32::from_be_bytes(*b"acct");
const SERVICE_ITEM_ATTRIBUTE: u32 = u32::from_be_bytes(*b"svce");

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTrustedApplicationCreateFromPath(
        path: *const std::os::raw::c_char,
        application: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecTrustedApplicationCopyData(application: CFTypeRef, data: *mut CFDataRef) -> OSStatus;
    fn SecAccessCreate(
        descriptor: CFStringRef,
        trusted_list: CFArrayRef,
        access: *mut SecAccessRef,
    ) -> OSStatus;
    fn SecAccessCopyMatchingACLList(access: SecAccessRef, authorization: CFTypeRef) -> CFArrayRef;
    fn SecACLCopyContents(
        acl: CFTypeRef,
        application_list: *mut CFArrayRef,
        description: *mut CFStringRef,
        prompt_selector: *mut u16,
    ) -> OSStatus;
    fn SecKeychainItemCopyAccess(item: SecKeychainItemRef, access: *mut SecAccessRef) -> OSStatus;
    fn SecKeychainItemCreateFromContent(
        item_class: u32,
        attributes: *mut SecKeychainAttributeList,
        length: u32,
        data: *const std::ffi::c_void,
        keychain: security_framework_sys::base::SecKeychainRef,
        initial_access: SecAccessRef,
        item: *mut SecKeychainItemRef,
    ) -> OSStatus;
    fn SecKeychainItemModifyAttributesAndData(
        item: SecKeychainItemRef,
        attributes: *const SecKeychainAttributeList,
        length: u32,
        data: *const std::ffi::c_void,
    ) -> OSStatus;
    static kSecACLAuthorizationDecrypt: CFStringRef;
}

/// Closed failure returned by the ACL wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeychainAclError {
    /// An executable path cannot form a trusted application.
    InvalidExecutable,
    /// A service or account identity is empty, oversized or contains NUL.
    InvalidItemIdentity,
    /// The requested or observed ACL is absent or broader than expected.
    AccessDenied,
    /// Security.framework returned another closed operation failure.
    OperationFailed,
}

/// Creates an empty generic-password item atomically under the exact ACL.
///
/// Credential bytes are intentionally absent from this API. The safe caller
/// must populate the returned item and delete it if population fails.
///
/// # Errors
///
/// Returns a closed error when the item identity is invalid or Keychain cannot
/// create the empty item with the supplied initial access.
pub fn create_empty_generic_password(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
    exact: &ExactKeychainAccess,
) -> Result<SecKeychainItem, KeychainAclError> {
    if service.is_empty()
        || account.is_empty()
        || service.as_bytes().contains(&0)
        || account.as_bytes().contains(&0)
    {
        return Err(KeychainAclError::InvalidItemIdentity);
    }
    let service_length =
        u32::try_from(service.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?;
    let account_length =
        u32::try_from(account.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?;
    let mut attributes = [
        SecKeychainAttribute {
            tag: SERVICE_ITEM_ATTRIBUTE,
            length: service_length,
            data: service.as_ptr().cast_mut().cast(),
        },
        SecKeychainAttribute {
            tag: ACCOUNT_ITEM_ATTRIBUTE,
            length: account_length,
            data: account.as_ptr().cast_mut().cast(),
        },
    ];
    let mut attribute_list = SecKeychainAttributeList {
        count: u32::try_from(attributes.len())
            .map_err(|_| KeychainAclError::InvalidItemIdentity)?,
        attr: attributes.as_mut_ptr(),
    };
    let mut item = ptr::null_mut();
    // SAFETY: attribute buffers and all Security.framework objects remain live
    // for the call. Data is deliberately NULL/zero-length, and `item` is a
    // valid writable out-pointer consumed under the create rule below.
    status(unsafe {
        SecKeychainItemCreateFromContent(
            GENERIC_PASSWORD_ITEM_CLASS,
            &raw mut attribute_list,
            0,
            ptr::null(),
            keychain.as_concrete_TypeRef(),
            exact.access.as_concrete_TypeRef(),
            &raw mut item,
        )
    })?;
    if item.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    // SAFETY: the create function returned a non-null retained item reference.
    Ok(unsafe { SecKeychainItem::wrap_under_create_rule(item) })
}

/// Exact trusted-application decrypt access plus its canonical set digest.
pub struct ExactKeychainAccess {
    access: SecAccess,
    digest: [u8; 32],
}

impl ExactKeychainAccess {
    /// Creates an access object containing only the canonical writer and reader.
    ///
    /// # Errors
    ///
    /// Returns a closed error when either trusted application or the access
    /// object cannot be created.
    pub fn new(writer: &Path, reader: &Path) -> Result<Self, KeychainAclError> {
        let writer = trusted_application(writer)?;
        let reader = trusted_application(reader)?;
        let digest = trusted_application_set_digest(&[&writer, &reader])?;
        let trusted_list = CFArray::from_CFTypes(&[writer, reader]);
        let descriptor = CFString::new(ACL_DESCRIPTOR);
        let mut access = ptr::null_mut();
        // SAFETY: every Core Foundation input is alive for the call and
        // `access` is a valid writable out-pointer consumed under create rule.
        status(unsafe {
            SecAccessCreate(
                descriptor.as_concrete_TypeRef(),
                trusted_list.as_concrete_TypeRef(),
                &raw mut access,
            )
        })?;
        if access.is_null() {
            return Err(KeychainAclError::AccessDenied);
        }
        Ok(Self {
            // SAFETY: `SecAccessCreate` returned a non-null retained reference.
            access: unsafe { SecAccess::wrap_under_create_rule(access) },
            digest,
        })
    }

    /// Returns the non-secret canonical trusted-application set digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Verifies that every decrypt ACL has exactly the enrolled application set.
///
/// # Errors
///
/// Returns [`KeychainAclError::AccessDenied`] for an absent, empty or broader ACL.
pub fn verify_item_access(
    item: &SecKeychainItem,
    expected_digest: [u8; 32],
) -> Result<(), KeychainAclError> {
    let mut access = ptr::null_mut();
    // SAFETY: `item` is live and `access` is a valid writable out-pointer.
    status(unsafe { SecKeychainItemCopyAccess(item.as_concrete_TypeRef(), &raw mut access) })?;
    if access.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    // SAFETY: `SecKeychainItemCopyAccess` returned a non-null retained reference.
    let access = unsafe { SecAccess::wrap_under_create_rule(access) };
    // SAFETY: the access reference and static authorization tag are valid.
    let acl_list = unsafe {
        SecAccessCopyMatchingACLList(
            access.as_concrete_TypeRef(),
            kSecACLAuthorizationDecrypt.cast(),
        )
    };
    if acl_list.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    // SAFETY: the Copy function returned a non-null retained CFArray.
    let acl_list = unsafe { CFArray::<CFType>::wrap_under_create_rule(acl_list) };
    if acl_list.is_empty() {
        return Err(KeychainAclError::AccessDenied);
    }
    for acl in acl_list.iter() {
        let mut applications = ptr::null();
        let mut description = ptr::null();
        let mut prompt_selector = 0;
        // SAFETY: `acl` is retained by `acl_list`; all outputs are valid writable
        // pointers and are handled under the documented create/copy rules below.
        status(unsafe {
            SecACLCopyContents(
                acl.as_CFTypeRef(),
                &raw mut applications,
                &raw mut description,
                &raw mut prompt_selector,
            )
        })?;
        if !description.is_null() {
            // SAFETY: `SecACLCopyContents` returned a retained non-null string.
            let _description = unsafe { CFString::wrap_under_create_rule(description) };
        }
        if applications.is_null() {
            return Err(KeychainAclError::AccessDenied);
        }
        if prompt_selector & PROMPT_REQUIRE_PASSPHRASE != 0 {
            return Err(KeychainAclError::AccessDenied);
        }
        // SAFETY: `SecACLCopyContents` returned a retained non-null array.
        let applications = unsafe { CFArray::<CFType>::wrap_under_create_rule(applications) };
        let digests = applications
            .iter()
            .map(|application| trusted_application_digest(application.as_CFTypeRef()))
            .collect::<Result<Vec<_>, _>>()?;
        if digest_set(digests)? != expected_digest {
            return Err(KeychainAclError::AccessDenied);
        }
    }
    Ok(())
}

/// Deletes one exact keychain item and propagates the OS result.
///
/// # Errors
///
/// Returns a closed failure when the item cannot be deleted.
pub fn delete_item(item: &SecKeychainItem) -> Result<(), KeychainAclError> {
    // SAFETY: `item` is a live Security.framework object for the duration of the call.
    status(unsafe { SecKeychainItemDelete(item.as_concrete_TypeRef()) })
}

/// Atomically changes only the service identity of an existing item.
///
/// The password bytes and ACL are left unchanged. This is used to restore a
/// verified migration backup without ever materializing another plaintext
/// copy in this unsafe boundary.
///
/// # Errors
///
/// Returns a closed failure when the service identity is invalid or Keychain
/// cannot commit the attribute update.
pub fn rename_item_service(item: &SecKeychainItem, service: &str) -> Result<(), KeychainAclError> {
    if service.is_empty() || service.as_bytes().contains(&0) {
        return Err(KeychainAclError::InvalidItemIdentity);
    }
    let mut attribute = SecKeychainAttribute {
        tag: SERVICE_ITEM_ATTRIBUTE,
        length: u32::try_from(service.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?,
        data: service.as_ptr().cast_mut().cast(),
    };
    let attributes = SecKeychainAttributeList {
        count: 1,
        attr: &raw mut attribute,
    };
    // SAFETY: the service buffer and attribute list remain live for the call.
    // NULL data means the existing password is not modified.
    status(unsafe {
        SecKeychainItemModifyAttributesAndData(
            item.as_concrete_TypeRef(),
            &raw const attributes,
            0,
            ptr::null(),
        )
    })
}

fn trusted_application(path: &Path) -> Result<CFType, KeychainAclError> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| KeychainAclError::InvalidExecutable)?;
    let mut application = ptr::null();
    // SAFETY: `path` is NUL-terminated and alive, and `application` is a valid
    // writable out-pointer handled under the create rule below.
    status(unsafe { SecTrustedApplicationCreateFromPath(path.as_ptr(), &raw mut application) })?;
    if application.is_null() {
        return Err(KeychainAclError::InvalidExecutable);
    }
    // SAFETY: the create function returned a non-null retained CF object.
    Ok(unsafe { CFType::wrap_under_create_rule(application) })
}

fn trusted_application_set_digest(applications: &[&CFType]) -> Result<[u8; 32], KeychainAclError> {
    let digests = applications
        .iter()
        .map(|application| trusted_application_digest(application.as_CFTypeRef()))
        .collect::<Result<Vec<_>, _>>()?;
    digest_set(digests)
}

fn trusted_application_digest(application: CFTypeRef) -> Result<[u8; 32], KeychainAclError> {
    let mut data = ptr::null();
    // SAFETY: `application` is a live trusted-application CF object and `data`
    // is a valid writable out-pointer handled under the copy rule below.
    status(unsafe { SecTrustedApplicationCopyData(application, &raw mut data) })?;
    if data.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    // SAFETY: the Copy function returned a non-null retained CFData.
    let data = unsafe { CFData::wrap_under_create_rule(data) };
    if data.bytes().is_empty() {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(Sha256::digest(data.bytes()).into())
}

fn digest_set(mut digests: Vec<[u8; 32]>) -> Result<[u8; 32], KeychainAclError> {
    digests.sort_unstable();
    digests.dedup();
    if digests.is_empty() {
        return Err(KeychainAclError::AccessDenied);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"gocode-provider-credential-acl-set-v1\0");
    hasher.update(
        u32::try_from(digests.len())
            .map_err(|_| KeychainAclError::AccessDenied)?
            .to_be_bytes(),
    );
    for digest in digests {
        hasher.update(digest);
    }
    Ok(hasher.finalize().into())
}

const fn status(code: OSStatus) -> Result<(), KeychainAclError> {
    if code == errSecSuccess {
        Ok(())
    } else if matches!(
        code,
        ERR_SEC_AUTH_FAILED
            | ERR_SEC_INTERACTION_NOT_ALLOWED
            | ERR_SEC_NO_ACCESS_FOR_ITEM
            | ERR_SEC_INVALID_OWNER_EDIT
    ) {
        Err(KeychainAclError::AccessDenied)
    } else {
        Err(KeychainAclError::OperationFailed)
    }
}
