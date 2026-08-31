use std::ffi::{CStr, CString};
use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;

#[cfg(test)]
use std::sync::atomic::{AtomicIsize, Ordering};

use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::{CFRelease, CFType, CFTypeRef, OSStatus, TCFType as _};
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::string::{CFString, CFStringRef};
use security_framework::os::macos::access::SecAccess;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::keychain_item::SecKeychainItem;
use security_framework_sys::base::{
    SecAccessRef, SecKeychainAttribute, SecKeychainAttributeList, SecKeychainItemRef,
    errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecSuccess,
};
use security_framework_sys::keychain_item::{SecKeychainItemDelete, SecKeychainItemFreeContent};
use sha2::{Digest as _, Sha256};

const ACL_DESCRIPTOR: &str = "Runne provider credential";
const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25_300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: OSStatus = -25_308;
const ERR_SEC_NO_ACCESS_FOR_ITEM: OSStatus = -25_243;
const ERR_SEC_INVALID_OWNER_EDIT: OSStatus = -25_244;
const GENERIC_PASSWORD_ITEM_CLASS: u32 = u32::from_be_bytes(*b"genp");
const ACCOUNT_ITEM_ATTRIBUTE: u32 = u32::from_be_bytes(*b"acct");
const SERVICE_ITEM_ATTRIBUTE: u32 = u32::from_be_bytes(*b"svce");
const GENERIC_ITEM_ATTRIBUTE: u32 = u32::from_be_bytes(*b"gena");
const DARWIN_USER_CACHE_DIRECTORY: libc::c_int = 65_538;
const PROVIDER_CREDENTIAL_LOCK_DIRECTORY: &[u8] = b"dev.runne.provider-credential.v1.lock\0";

#[cfg(test)]
static LIVE_COPIED_APPLICATION_LISTS: AtomicIsize = AtomicIsize::new(0);

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
    #[cfg(test)]
    fn SecACLSetContents(
        acl: CFTypeRef,
        application_list: CFArrayRef,
        description: CFStringRef,
        prompt_selector: u16,
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
    fn SecKeychainItemCopyContent(
        item: SecKeychainItemRef,
        item_class: *mut u32,
        attributes: *mut SecKeychainAttributeList,
        length: *mut u32,
        data: *mut *mut std::ffi::c_void,
    ) -> OSStatus;
    fn SecKeychainItemModifyAttributesAndData(
        item: SecKeychainItemRef,
        attributes: *const SecKeychainAttributeList,
        length: u32,
        data: *const std::ffi::c_void,
    ) -> OSStatus;
    fn SecKeychainSearchCreateFromAttributes(
        keychain_or_array: CFTypeRef,
        item_class: u32,
        attributes: *const SecKeychainAttributeList,
        search: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecKeychainSearchCopyNext(search: CFTypeRef, item: *mut SecKeychainItemRef) -> OSStatus;
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
    /// A profile digest does not match the guard that protects it.
    InvalidProfileBinding,
    /// A transaction seal is malformed or cannot be verified.
    InvalidSeal,
    /// Security.framework returned another closed operation failure.
    OperationFailed,
}

/// Owns a non-null retained CoreFoundation-compatible out-parameter until its
/// concrete safe wrapper takes over that +1 reference.
struct RetainedCfOutput(CFTypeRef);

impl RetainedCfOutput {
    const fn new<T>(output: *const T) -> Self {
        Self(output.cast())
    }

    fn disarm(mut self) {
        self.0 = ptr::null();
    }
}
impl Drop for RetainedCfOutput {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the guard is created only for a +1 Create/Copy output and
            // is disarmed when ownership moves into a concrete safe wrapper.
            unsafe { CFRelease(self.0) };
        }
    }
}

struct KeychainContentCleanup<F>
where
    F: FnOnce(*mut SecKeychainAttributeList) -> OSStatus,
{
    attributes: *mut SecKeychainAttributeList,
    free_content: Option<F>,
    armed: bool,
}

impl<F> KeychainContentCleanup<F>
where
    F: FnOnce(*mut SecKeychainAttributeList) -> OSStatus,
{
    const fn new(attributes: *mut SecKeychainAttributeList, free_content: F, armed: bool) -> Self {
        Self {
            attributes,
            free_content: Some(free_content),
            armed,
        }
    }

    fn free_once(&mut self) -> Option<OSStatus> {
        if !self.armed {
            return None;
        }
        self.armed = false;
        self.free_content
            .take()
            .map(|free_content| free_content(self.attributes))
    }

    fn finish(mut self) -> Result<(), KeychainAclError> {
        self.free_once().map_or(Ok(()), status)
    }
}

impl<F> Drop for KeychainContentCleanup<F>
where
    F: FnOnce(*mut SecKeychainAttributeList) -> OSStatus,
{
    fn drop(&mut self) {
        let _ = self.free_once();
    }
}

/// Kernel-held lock for all provider credential Keychain operations.
pub struct ProviderCredentialProcessLock {
    _directory: File,
}

impl ProviderCredentialProcessLock {
    /// Acquires the fixed per-user lock independently of ambient environment.
    ///
    /// The lock is the owner-only directory inode itself, so there is no lock
    /// file that normal participants can unlink and recreate.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the Darwin user cache root or lock
    /// directory is not an owner-only, non-symlink directory.
    pub fn acquire() -> Result<Self, KeychainAclError> {
        let cache_path = darwin_user_cache_directory()?;
        let cache = open_validated_directory(&cache_path)?;
        let lock_name = CStr::from_bytes_with_nul(PROVIDER_CREDENTIAL_LOCK_DIRECTORY)
            .map_err(|_| KeychainAclError::OperationFailed)?;
        // SAFETY: cache fd and NUL-terminated name are live. EEXIST is accepted
        // only after opening and validating the existing directory below.
        let mkdir_status = unsafe { libc::mkdirat(cache.as_raw_fd(), lock_name.as_ptr(), 0o700) };
        if mkdir_status != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
        {
            return Err(KeychainAclError::OperationFailed);
        }
        // SAFETY: the validated cache directory and NUL-terminated relative
        // name are live. O_NOFOLLOW rejects a symlink as the final component.
        let lock_fd = unsafe {
            libc::openat(
                cache.as_raw_fd(),
                lock_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if lock_fd < 0 {
            return Err(KeychainAclError::OperationFailed);
        }
        // SAFETY: openat returned a new owned descriptor.
        let directory = unsafe { File::from_raw_fd(lock_fd) };
        validate_owner_only_directory(&directory)?;
        validate_directory_entry(cache.as_raw_fd(), lock_name, &directory)?;
        // SAFETY: directory fd remains live in the returned guard; LOCK_EX is
        // released by the kernel when the descriptor is closed or process dies.
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(KeychainAclError::OperationFailed);
        }
        validate_owner_only_directory(&directory)?;
        validate_directory_entry(cache.as_raw_fd(), lock_name, &directory)?;
        Ok(Self {
            _directory: directory,
        })
    }
}
