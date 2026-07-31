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
    status(unsafe {
        SecKeychainItemCreateFromContent(
            GENERIC_PASSWORD_ITEM_CLASS,
            &raw mut attribute_list,
            0,
            ptr::null(),
            keychain.as_concrete_TypeRef().cast(),
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

/// Non-secret generic attribute and item reference for one exact password item.
pub struct GenericPasswordMetadata {
    /// Caller-defined non-secret metadata bytes.
    pub bytes: Vec<u8>,
    /// Exact native item reference used for ACL verification and lifecycle work.
    pub item: SecKeychainItem,
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
    status(unsafe {
        SecKeychainSearchCreateFromAttributes(
            keychain.as_concrete_TypeRef().cast(),
            GENERIC_PASSWORD_ITEM_CLASS,
            &raw const query,
            &raw mut search,
        )
    })?;
    if search.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    // SAFETY: the create call returned a non-null retained CF object.
    let search = unsafe { CFType::wrap_under_create_rule(search) };
    let mut item = ptr::null_mut();
    // SAFETY: search is live and item is a valid retained out-pointer.
    let item_status = unsafe { SecKeychainSearchCopyNext(search.as_CFTypeRef(), &raw mut item) };
    if item_status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(None);
    }
    status(item_status)?;
    if item.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    // SAFETY: the copy call returned a non-null retained item reference.
    let item = unsafe { SecKeychainItem::wrap_under_create_rule(item) };
    let mut metadata_attribute = SecKeychainAttribute {
        tag: GENERIC_ITEM_ATTRIBUTE,
        length: 0,
        data: ptr::null_mut(),
    };
    let mut metadata_list = SecKeychainAttributeList {
        count: 1,
        attr: &raw mut metadata_attribute,
    };
    // SAFETY: item and metadata list are live. Password length/data outputs are
    // NULL, so only the requested non-secret generic attribute is materialized.
    status(unsafe {
        SecKeychainItemCopyContent(
            item.as_concrete_TypeRef(),
            ptr::null_mut(),
            &raw mut metadata_list,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    })?;
    let bytes = if metadata_attribute.length == 0 || metadata_attribute.data.is_null() {
        Vec::new()
    } else {
        // SAFETY: CopyContent returned a buffer of the reported length, kept
        // alive until SecKeychainItemFreeContent below.
        unsafe {
            std::slice::from_raw_parts(
                metadata_attribute.data.cast::<u8>(),
                usize::try_from(metadata_attribute.length)
                    .map_err(|_| KeychainAclError::OperationFailed)?,
            )
            .to_vec()
        }
    };
    // SAFETY: metadata_list was populated by SecKeychainItemCopyContent and is
    // released exactly once; no password data buffer was requested.
    status(unsafe { SecKeychainItemFreeContent(&raw mut metadata_list, ptr::null_mut()) })?;
    if bytes.is_empty() {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(Some(GenericPasswordMetadata { bytes, item }))
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
        if !prompt_selector_is_unconditional(prompt_selector) {
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

const fn prompt_selector_is_unconditional(prompt_selector: u16) -> bool {
    prompt_selector == 0
}

#[cfg(test)]
mod tests {
    use super::prompt_selector_is_unconditional;

    #[test]
    fn every_nonzero_prompt_selector_is_rejected() {
        assert!(prompt_selector_is_unconditional(0));
        for prompt_selector in [1, 2, 4, 8, u16::MAX] {
            assert!(!prompt_selector_is_unconditional(prompt_selector));
        }
    }
}
