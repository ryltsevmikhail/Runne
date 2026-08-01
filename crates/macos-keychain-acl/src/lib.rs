//! Narrow safe wrapper for legacy macOS Keychain executable ACL APIs.
//!
//! The rest of the workspace forbids unsafe code. This crate contains the
//! minimum auditable FFI required to create and verify a generic-password
//! decrypt ACL. It never receives credential bytes.

#![cfg(target_os = "macos")]

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

const ACL_DESCRIPTOR: &str = "GOCODE provider credential";
const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25_300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: OSStatus = -25_308;
const ERR_SEC_NO_ACCESS_FOR_ITEM: OSStatus = -25_243;
const ERR_SEC_INVALID_OWNER_EDIT: OSStatus = -25_244;
const GENERIC_PASSWORD_ITEM_CLASS: u32 = u32::from_be_bytes(*b"genp");
const ACCOUNT_ITEM_ATTRIBUTE: u32 = u32::from_be_bytes(*b"acct");
const SERVICE_ITEM_ATTRIBUTE: u32 = u32::from_be_bytes(*b"svce");
const GENERIC_ITEM_ATTRIBUTE: u32 = u32::from_be_bytes(*b"gena");
const DARWIN_USER_CACHE_DIRECTORY: libc::c_int = 65_538;
const PROVIDER_CREDENTIAL_LOCK_DIRECTORY: &[u8] = b"dev.gocode.provider-credential.v1.lock\0";

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
    #[cfg(test)]
    fn SecKeychainItemSetAccess(item: SecKeychainItemRef, access: SecAccessRef) -> OSStatus;
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

fn darwin_user_cache_directory() -> Result<CString, KeychainAclError> {
    // SAFETY: a NULL/zero probe is the documented confstr size query.
    let required = unsafe { libc::confstr(DARWIN_USER_CACHE_DIRECTORY, ptr::null_mut(), 0) };
    if required < 2 {
        return Err(KeychainAclError::OperationFailed);
    }
    let mut bytes = vec![0_u8; required];
    // SAFETY: buffer is writable for exactly `required` bytes.
    let written = unsafe {
        libc::confstr(
            DARWIN_USER_CACHE_DIRECTORY,
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if written != required {
        return Err(KeychainAclError::OperationFailed);
    }
    CString::from_vec_with_nul(bytes).map_err(|_| KeychainAclError::OperationFailed)
}

fn open_validated_directory(path: &CString) -> Result<File, KeychainAclError> {
    // SAFETY: path is NUL-terminated. O_NOFOLLOW rejects a symlink final
    // component; the Darwin cache path itself comes from confstr, not env.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(KeychainAclError::OperationFailed);
    }
    // SAFETY: open returned a new owned descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    validate_owner_only_directory(&directory)?;
    Ok(directory)
}

fn validate_owner_only_directory(directory: &File) -> Result<libc::stat, KeychainAclError> {
    // SAFETY: zeroed stat is valid output storage for fstat.
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: directory fd is live and metadata is a valid out-pointer.
    if unsafe { libc::fstat(directory.as_raw_fd(), &raw mut metadata) } != 0 {
        return Err(KeychainAclError::OperationFailed);
    }
    // SAFETY: geteuid has no preconditions.
    let current_uid = unsafe { libc::geteuid() };
    if metadata.st_uid != current_uid
        || metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_mode & 0o077 != 0
        || metadata.st_nlink == 0
    {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(metadata)
}

fn validate_directory_entry(
    parent_fd: libc::c_int,
    name: &CStr,
    directory: &File,
) -> Result<(), KeychainAclError> {
    let opened = validate_owner_only_directory(directory)?;
    // SAFETY: zeroed stat is valid output storage for fstatat.
    let mut linked = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: parent fd, NUL-terminated relative name and output are valid.
    if unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            &raw mut linked,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(KeychainAclError::AccessDenied);
    }
    if linked.st_dev != opened.st_dev
        || linked.st_ino != opened.st_ino
        || linked.st_uid != opened.st_uid
        || linked.st_mode & libc::S_IFMT != libc::S_IFDIR
        || linked.st_mode & 0o077 != 0
    {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(())
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
    metadata: &[u8],
    exact: &ExactKeychainAccess,
) -> Result<SecKeychainItem, KeychainAclError> {
    if service.is_empty()
        || account.is_empty()
        || service.as_bytes().contains(&0)
        || account.as_bytes().contains(&0)
        || metadata.is_empty()
    {
        return Err(KeychainAclError::InvalidItemIdentity);
    }
    let service_length =
        u32::try_from(service.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?;
    let account_length =
        u32::try_from(account.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?;
    let metadata_length =
        u32::try_from(metadata.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?;
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
        SecKeychainAttribute {
            tag: GENERIC_ITEM_ATTRIBUTE,
            length: metadata_length,
            data: metadata.as_ptr().cast_mut().cast(),
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
    let create_status = unsafe {
        SecKeychainItemCreateFromContent(
            GENERIC_PASSWORD_ITEM_CLASS,
            &raw mut attribute_list,
            0,
            ptr::null(),
            keychain.as_concrete_TypeRef().cast(),
            exact.access.as_concrete_TypeRef(),
            &raw mut item,
        )
    };
    let item_owner = RetainedCfOutput::new(item);
    status(create_status)?;
    if item.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    item_owner.disarm();
    // SAFETY: the create function returned a non-null retained item reference.
    Ok(unsafe { SecKeychainItem::wrap_under_create_rule(item) })
}

/// Non-secret generic attribute and item reference for one exact password item.
pub struct GenericPasswordMetadata {
    /// Caller-defined non-secret metadata bytes.
    pub bytes: Vec<u8>,
    /// Exact native item reference used for ACL verification and lifecycle work.
    pub item: SecKeychainItem,
}

/// Checks whether one exact generic-password item exists without requesting
/// password data or any optional item metadata.
///
/// # Errors
///
/// Returns a closed failure for malformed identities or Security.framework
/// failures other than an absent item.
pub fn generic_password_exists(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
) -> Result<bool, KeychainAclError> {
    if service.is_empty()
        || account.is_empty()
        || service.as_bytes().contains(&0)
        || account.as_bytes().contains(&0)
    {
        return Err(KeychainAclError::InvalidItemIdentity);
    }
    let mut query_attributes = [
        SecKeychainAttribute {
            tag: SERVICE_ITEM_ATTRIBUTE,
            length: u32::try_from(service.len())
                .map_err(|_| KeychainAclError::InvalidItemIdentity)?,
            data: service.as_ptr().cast_mut().cast(),
        },
        SecKeychainAttribute {
            tag: ACCOUNT_ITEM_ATTRIBUTE,
            length: u32::try_from(account.len())
                .map_err(|_| KeychainAclError::InvalidItemIdentity)?,
            data: account.as_ptr().cast_mut().cast(),
        },
    ];
    let query = SecKeychainAttributeList {
        count: u32::try_from(query_attributes.len())
            .map_err(|_| KeychainAclError::InvalidItemIdentity)?,
        attr: query_attributes.as_mut_ptr(),
    };
    let mut search = ptr::null();
    // SAFETY: query buffers and keychain stay live, and `search` is a valid
    // retained CF out-pointer consumed below.
    let search_status = unsafe {
        SecKeychainSearchCreateFromAttributes(
            keychain.as_concrete_TypeRef().cast(),
            GENERIC_PASSWORD_ITEM_CLASS,
            &raw const query,
            &raw mut search,
        )
    };
    let search_owner = RetainedCfOutput::new(search);
    status(search_status)?;
    if search.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    search_owner.disarm();
    // SAFETY: the create call returned a non-null retained CF object.
    let search = unsafe { CFType::wrap_under_create_rule(search) };
    let mut item = ptr::null_mut();
    // SAFETY: search is live and item is a valid retained out-pointer. This
    // existence-only call has no password length/data output parameters.
    let item_status = unsafe { SecKeychainSearchCopyNext(search.as_CFTypeRef(), &raw mut item) };
    let item_owner = RetainedCfOutput::new(item);
    if item_status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(false);
    }
    status(item_status)?;
    if item.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    item_owner.disarm();
    // SAFETY: the copy call returned a non-null retained item reference; the
    // wrapper releases it without reading any attributes or secret bytes.
    drop(unsafe { SecKeychainItem::wrap_under_create_rule(item) });
    Ok(true)
}

fn copy_nonsecret_metadata_with<C, F>(
    copy_content: C,
    free_content: F,
) -> Result<Vec<u8>, KeychainAclError>
where
    C: FnOnce(*mut SecKeychainAttributeList) -> OSStatus,
    F: FnOnce(*mut SecKeychainAttributeList) -> OSStatus,
{
    let mut metadata_attribute = SecKeychainAttribute {
        tag: GENERIC_ITEM_ATTRIBUTE,
        length: 0,
        data: ptr::null_mut(),
    };
    let mut metadata_list = SecKeychainAttributeList {
        count: 1,
        attr: &raw mut metadata_attribute,
    };
    let copy_status = copy_content(&raw mut metadata_list);
    let should_free = copy_status == errSecSuccess
        || metadata_attribute.length != 0
        || !metadata_attribute.data.is_null();
    let cleanup = KeychainContentCleanup::new(&raw mut metadata_list, free_content, should_free);
    status(copy_status)?;
    let bytes = if metadata_attribute.length == 0 || metadata_attribute.data.is_null() {
        Vec::new()
    } else {
        // SAFETY: the caller populated a buffer of the reported length and it
        // stays live until `free_content` below.
        unsafe {
            std::slice::from_raw_parts(
                metadata_attribute.data.cast::<u8>(),
                metadata_attribute.length as usize,
            )
            .to_vec()
        }
    };
    cleanup.finish()?;
    Ok(bytes)
}

/// Finds one generic-password item and returns only its non-secret metadata.
///
/// The password data output is deliberately omitted from every native call.
///
/// # Errors
///
/// Returns a closed failure for malformed identities or Security.framework
/// failures other than an absent item.
pub fn find_generic_password_metadata(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
) -> Result<Option<GenericPasswordMetadata>, KeychainAclError> {
    if service.is_empty()
        || account.is_empty()
        || service.as_bytes().contains(&0)
        || account.as_bytes().contains(&0)
    {
        return Err(KeychainAclError::InvalidItemIdentity);
    }
    let mut query_attributes = [
        SecKeychainAttribute {
            tag: SERVICE_ITEM_ATTRIBUTE,
            length: u32::try_from(service.len())
                .map_err(|_| KeychainAclError::InvalidItemIdentity)?,
            data: service.as_ptr().cast_mut().cast(),
        },
        SecKeychainAttribute {
            tag: ACCOUNT_ITEM_ATTRIBUTE,
            length: u32::try_from(account.len())
                .map_err(|_| KeychainAclError::InvalidItemIdentity)?,
            data: account.as_ptr().cast_mut().cast(),
        },
    ];
    let query = SecKeychainAttributeList {
        count: u32::try_from(query_attributes.len())
            .map_err(|_| KeychainAclError::InvalidItemIdentity)?,
        attr: query_attributes.as_mut_ptr(),
    };
    let mut search = ptr::null();
    // SAFETY: query buffers and keychain stay live, and `search` is a valid
    // retained CF out-pointer consumed below.
    let search_status = unsafe {
        SecKeychainSearchCreateFromAttributes(
            keychain.as_concrete_TypeRef().cast(),
            GENERIC_PASSWORD_ITEM_CLASS,
            &raw const query,
            &raw mut search,
        )
    };
    let search_owner = RetainedCfOutput::new(search);
    status(search_status)?;
    if search.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    search_owner.disarm();
    // SAFETY: the create call returned a non-null retained CF object.
    let search = unsafe { CFType::wrap_under_create_rule(search) };
    let mut item = ptr::null_mut();
    // SAFETY: search is live and item is a valid retained out-pointer.
    let item_status = unsafe { SecKeychainSearchCopyNext(search.as_CFTypeRef(), &raw mut item) };
    let item_owner = RetainedCfOutput::new(item);
    if item_status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(None);
    }
    status(item_status)?;
    if item.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    item_owner.disarm();
    // SAFETY: the copy call returned a non-null retained item reference.
    let item = unsafe { SecKeychainItem::wrap_under_create_rule(item) };
    // SAFETY: item and metadata list are live. Password length/data outputs are
    // NULL, so only the requested non-secret generic attribute is materialized.
    let bytes = copy_nonsecret_metadata_with(
        |metadata_list| unsafe {
            SecKeychainItemCopyContent(
                item.as_concrete_TypeRef(),
                ptr::null_mut(),
                metadata_list,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        |metadata_list| unsafe { SecKeychainItemFreeContent(metadata_list, ptr::null_mut()) },
    )?;
    if bytes.is_empty() {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(Some(GenericPasswordMetadata { bytes, item }))
}

fn copy_acl_contents_with<C>(copy_contents: C) -> Result<(CFArray<CFType>, u16), KeychainAclError>
where
    C: FnOnce(*mut CFArrayRef, *mut CFStringRef, *mut u16) -> OSStatus,
{
    let mut applications = ptr::null();
    let mut description = ptr::null();
    let mut prompt_selector = 0;
    let copy_status = copy_contents(
        &raw mut applications,
        &raw mut description,
        &raw mut prompt_selector,
    );
    let applications_owner = RetainedCfOutput::new(applications);
    let description_owner = RetainedCfOutput::new(description);
    status(copy_status)?;
    #[cfg(test)]
    if !applications.is_null() {
        LIVE_COPIED_APPLICATION_LISTS.fetch_add(1, Ordering::Relaxed);
    }
    if !description.is_null() {
        description_owner.disarm();
        // SAFETY: the copy call returned a retained non-null string.
        let _description = unsafe { CFString::wrap_under_create_rule(description) };
    }
    if applications.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    applications_owner.disarm();
    // SAFETY: the copy call returned a retained non-null array.
    let applications = unsafe { CFArray::<CFType>::wrap_under_create_rule(applications) };
    #[cfg(test)]
    LIVE_COPIED_APPLICATION_LISTS.fetch_sub(1, Ordering::Relaxed);
    Ok((applications, prompt_selector))
}

fn copy_acl_contents(acl: &CFType) -> Result<(CFArray<CFType>, u16), KeychainAclError> {
    copy_acl_contents_with(|applications, description, prompt_selector| {
        // SAFETY: `acl` is retained by its containing list and all outputs are
        // valid writable pointers consumed under the Copy Rule by the helper.
        unsafe {
            SecACLCopyContents(
                acl.as_CFTypeRef(),
                applications,
                description,
                prompt_selector,
            )
        }
    })
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
        let access_status = unsafe {
            SecAccessCreate(
                descriptor.as_concrete_TypeRef(),
                trusted_list.as_concrete_TypeRef(),
                &raw mut access,
            )
        };
        let access_owner = RetainedCfOutput::new(access);
        status(access_status)?;
        if access.is_null() {
            return Err(KeychainAclError::AccessDenied);
        }
        access_owner.disarm();
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
    let access_status =
        unsafe { SecKeychainItemCopyAccess(item.as_concrete_TypeRef(), &raw mut access) };
    let access_owner = RetainedCfOutput::new(access);
    status(access_status)?;
    if access.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    access_owner.disarm();
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
        let (applications, prompt_selector) = copy_acl_contents(&acl)?;
        if !prompt_selector_is_unconditional(prompt_selector) {
            return Err(KeychainAclError::AccessDenied);
        }
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

/// Atomically replaces only the non-secret generic metadata attribute.
///
/// Password bytes and ACL are left unchanged.
///
/// # Errors
///
/// Returns a closed failure for empty metadata or a native update failure.
pub fn set_generic_password_metadata(
    item: &SecKeychainItem,
    metadata: &[u8],
) -> Result<(), KeychainAclError> {
    if metadata.is_empty() {
        return Err(KeychainAclError::InvalidItemIdentity);
    }
    let mut attribute = SecKeychainAttribute {
        tag: GENERIC_ITEM_ATTRIBUTE,
        length: u32::try_from(metadata.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?,
        data: metadata.as_ptr().cast_mut().cast(),
    };
    let attributes = SecKeychainAttributeList {
        count: 1,
        attr: &raw mut attribute,
    };
    // SAFETY: metadata and its attribute list remain live for the call. NULL
    // password data preserves the existing password bytes.
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
    let create_status =
        unsafe { SecTrustedApplicationCreateFromPath(path.as_ptr(), &raw mut application) };
    let application_owner = RetainedCfOutput::new(application);
    status(create_status)?;
    if application.is_null() {
        return Err(KeychainAclError::InvalidExecutable);
    }
    application_owner.disarm();
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
    let copy_status = unsafe { SecTrustedApplicationCopyData(application, &raw mut data) };
    let data_owner = RetainedCfOutput::new(data);
    status(copy_status)?;
    if data.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    data_owner.disarm();
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

const fn prompt_selector_is_unconditional(prompt_selector: u16) -> bool {
    prompt_selector == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestItem(SecKeychainItem);

    impl Drop for TestItem {
        fn drop(&mut self) {
            let _ = delete_item(&self.0);
        }
    }

    fn item_access(item: &SecKeychainItem) -> SecAccess {
        let mut access = ptr::null_mut();
        // SAFETY: item is live and access is a valid retained out-pointer.
        let access_status =
            unsafe { SecKeychainItemCopyAccess(item.as_concrete_TypeRef(), &raw mut access) };
        let access_owner = RetainedCfOutput::new(access);
        status(access_status).unwrap();
        assert!(!access.is_null());
        access_owner.disarm();
        // SAFETY: the copy call returned a retained access reference.
        unsafe { SecAccess::wrap_under_create_rule(access) }
    }

    fn decrypt_acl_list(access: &SecAccess) -> CFArray<CFType> {
        // SAFETY: access and the static authorization tag are live.
        let acl_list = unsafe {
            SecAccessCopyMatchingACLList(
                access.as_concrete_TypeRef(),
                kSecACLAuthorizationDecrypt.cast(),
            )
        };
        assert!(!acl_list.is_null());
        // SAFETY: the Copy call returned a retained array.
        unsafe { CFArray::wrap_under_create_rule(acl_list) }
    }

    fn copy_acl_applications(acl: &CFType) -> CFArray<CFType> {
        copy_acl_contents_with(|applications, description, prompt_selector| {
            // SAFETY: acl and all retained out-pointers are valid.
            unsafe {
                SecACLCopyContents(
                    acl.as_CFTypeRef(),
                    applications,
                    description,
                    prompt_selector,
                )
            }
        })
        .unwrap()
        .0
    }

    fn set_item_prompt_selector(item: &SecKeychainItem, prompt_selector: u16) {
        let access = item_access(item);
        let acl_list = decrypt_acl_list(&access);
        for acl in acl_list.iter() {
            let mut applications = ptr::null();
            let mut description = ptr::null();
            let mut existing_prompt_selector = 0;
            // SAFETY: acl and retained output pointers are valid.
            let copy_status = unsafe {
                SecACLCopyContents(
                    acl.as_CFTypeRef(),
                    &raw mut applications,
                    &raw mut description,
                    &raw mut existing_prompt_selector,
                )
            };
            let applications_owner = RetainedCfOutput::new(applications);
            let description_owner = RetainedCfOutput::new(description);
            status(copy_status).unwrap();
            assert!(!applications.is_null());
            assert!(!description.is_null());
            applications_owner.disarm();
            description_owner.disarm();
            // SAFETY: both copy outputs are retained and wrapped immediately.
            let applications = unsafe { CFArray::<CFType>::wrap_under_create_rule(applications) };
            let description = unsafe { CFString::wrap_under_create_rule(description) };
            // SAFETY: acl and wrapped contents stay live through the mutation.
            status(unsafe {
                SecACLSetContents(
                    acl.as_CFTypeRef(),
                    applications.as_concrete_TypeRef(),
                    description.as_concrete_TypeRef(),
                    prompt_selector,
                )
            })
            .unwrap();
        }
        // SAFETY: item and access are live for the native update.
        status(unsafe {
            SecKeychainItemSetAccess(item.as_concrete_TypeRef(), access.as_concrete_TypeRef())
        })
        .unwrap();
    }

    #[test]
    fn every_nonzero_prompt_selector_is_rejected() {
        assert!(prompt_selector_is_unconditional(0));
        for prompt_selector in [1, 2, 4, 8, u16::MAX] {
            assert!(!prompt_selector_is_unconditional(prompt_selector));
        }
    }

    #[test]
    fn acl_copy_error_releases_both_retained_outputs() {
        let element = CFString::new("retained application fixture");
        let applications = CFArray::from_CFTypes(&[element]);
        let description =
            CFString::new("retained description fixture long enough to avoid tagged storage");
        let applications_before = applications.retain_count();
        let description_before = description.retain_count();

        for _ in 0..64 {
            let result = copy_acl_contents_with(|applications_out, description_out, prompt| {
                // SAFETY: each fake Copy output receives its own +1 retain and
                // all output pointers are valid for this call.
                unsafe {
                    *applications_out =
                        core_foundation::base::CFRetain(applications.as_CFTypeRef()).cast();
                    *description_out =
                        core_foundation::base::CFRetain(description.as_CFTypeRef()).cast();
                    *prompt = 0;
                }
                -50
            });
            assert_eq!(result.err(), Some(KeychainAclError::OperationFailed));
        }

        let applications_after = applications.retain_count();
        let description_after = description.retain_count();
        for _ in applications_before..applications_after {
            // SAFETY: the RED implementation leaked one fake +1 retain per
            // iteration; release it so a failing regression does not leak.
            unsafe { core_foundation::base::CFRelease(applications.as_CFTypeRef()) };
        }
        for _ in description_before..description_after {
            // SAFETY: same cleanup for the fake retained description output.
            unsafe { core_foundation::base::CFRelease(description.as_CFTypeRef()) };
        }
        assert_eq!(applications_after, applications_before);
        assert_eq!(description_after, description_before);
    }

    #[test]
    fn metadata_copy_error_frees_populated_content_exactly_once() {
        let free_calls = std::cell::Cell::new(0);

        for _ in 0..64 {
            let allocation = std::cell::Cell::new(ptr::null_mut::<u8>());
            let result = copy_nonsecret_metadata_with(
                |metadata_list| {
                    let mut bytes = b"metadata".to_vec().into_boxed_slice();
                    let data = bytes.as_mut_ptr();
                    std::mem::forget(bytes);
                    allocation.set(data);
                    // SAFETY: the list points to the helper's live attribute.
                    unsafe {
                        let attribute = &mut *(*metadata_list).attr;
                        attribute.length = 8;
                        attribute.data = data.cast();
                    }
                    -50
                },
                |metadata_list| {
                    free_calls.set(free_calls.get() + 1);
                    // SAFETY: the fake Copy call allocated exactly the recorded
                    // eight-byte boxed slice and populated this attribute.
                    unsafe {
                        let attribute = &mut *(*metadata_list).attr;
                        drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
                            attribute.data.cast::<u8>(),
                            attribute.length as usize,
                        )));
                        attribute.data = ptr::null_mut();
                        attribute.length = 0;
                    }
                    allocation.set(ptr::null_mut());
                    errSecSuccess
                },
            );
            if !allocation.get().is_null() {
                // SAFETY: RED cleanup for the fake allocation when the missing
                // guard failed to invoke `free_content`.
                unsafe {
                    drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
                        allocation.get(),
                        8,
                    )));
                }
            }
            assert_eq!(result, Err(KeychainAclError::OperationFailed));
        }

        assert_eq!(free_calls.get(), 64);
    }

    #[test]
    fn repeated_native_prompt_acl_rejection_releases_copied_applications() {
        let _interaction = SecKeychain::disable_user_interaction().unwrap();
        let keychain = SecKeychain::default().unwrap();
        let current = std::env::current_exe().unwrap();
        let exact = ExactKeychainAccess::new(&current, &current).unwrap();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let item = TestItem(
            create_empty_generic_password(
                &keychain,
                &format!("dev.gocode.prompt-ownership-test.{unique}"),
                &format!("prompt-ownership-{unique}"),
                b"non-secret-test-metadata",
                &exact,
            )
            .unwrap(),
        );
        set_item_prompt_selector(&item.0, 1);
        let access = item_access(&item.0);
        let acl_list = decrypt_acl_list(&access);
        let applications = copy_acl_applications(&acl_list.get(0).unwrap());
        let before = applications.retain_count();
        LIVE_COPIED_APPLICATION_LISTS.store(0, Ordering::Relaxed);

        for _ in 0..256 {
            assert_eq!(
                verify_item_access(&item.0, exact.digest()),
                Err(KeychainAclError::AccessDenied)
            );
        }

        assert_eq!(applications.retain_count(), before);
        assert_eq!(LIVE_COPIED_APPLICATION_LISTS.load(Ordering::Relaxed), 0);
    }
}
