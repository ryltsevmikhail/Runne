use std::ffi::{CString, c_void};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;

use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::{CFRelease, CFType, CFTypeRef, TCFType as _};
use core_foundation::string::{CFString, CFStringRef};
use security_framework::os::macos::access::SecAccess;
use security_framework::os::macos::keychain_item::SecKeychainItem;

const ACL_NOT_SIMPLE: i32 = -25_240;
const INVALID_ACCESS_CREDENTIALS: i32 = -67_700;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTrustedApplicationCreateFromPath(path: *const i8, application: *mut CFTypeRef) -> i32;
    fn SecAccessCreateWithOwnerAndACL(
        user_id: libc::uid_t,
        group_id: libc::gid_t,
        owner_type: u32,
        acl_list: CFArrayRef,
        error: *mut CFTypeRef,
    ) -> *mut c_void;
    fn SecACLCreateWithSimpleContents(
        access: *mut c_void,
        applications: CFArrayRef,
        description: CFStringRef,
        prompt_selector: u16,
        acl: *mut CFTypeRef,
    ) -> i32;
    fn SecACLUpdateAuthorizations(acl: CFTypeRef, authorizations: CFArrayRef) -> i32;
    fn SecAccessCopyMatchingACLList(access: *mut c_void, authorization: CFTypeRef) -> CFArrayRef;
    fn SecACLCopyContents(
        acl: CFTypeRef,
        applications: *mut CFArrayRef,
        description: *mut CFStringRef,
        prompt_selector: *mut u16,
    ) -> i32;
    fn SecKeychainItemCopyAccess(item: *mut c_void, access: *mut *mut c_void) -> i32;
    fn SecKeychainItemSetAccess(item: *mut c_void, access: *mut c_void) -> i32;
    static kSecACLAuthorizationDecrypt: CFStringRef;
    static kSecACLAuthorizationEncrypt: CFStringRef;
    static kSecACLAuthorizationDelete: CFStringRef;
    static kSecACLAuthorizationKeychainItemRead: CFStringRef;
    static kSecACLAuthorizationKeychainItemModify: CFStringRef;
    static kSecACLAuthorizationKeychainItemDelete: CFStringRef;
    static kSecACLAuthorizationPartitionID: CFStringRef;
}

pub(super) fn complex_attacker_access(item: &SecKeychainItem) -> Result<SecAccess, &'static str> {
    let current = std::env::current_exe().map_err(|_| "unrelated-current-exe")?;
    let application = trusted_application(&current)?;
    let partition = copy_partition_description(item)?;
    let mut error = ptr::null();
    let access = unsafe {
        SecAccessCreateWithOwnerAndACL(
            libc::geteuid(),
            libc::getegid(),
            1,
            ptr::null(),
            &raw mut error,
        )
    };
    if !error.is_null() {
        unsafe { CFRelease(error) };
    }
    if access.is_null() || !error.is_null() {
        if !access.is_null() {
            unsafe { CFRelease(access.cast()) };
        }
        return Err("unrelated-access-create");
    }
    let access = unsafe { SecAccess::wrap_under_create_rule(access.cast()) };
    let applications = CFArray::from_CFTypes(&[application]);
    for authorization in unsafe {
        [
            kSecACLAuthorizationDecrypt,
            kSecACLAuthorizationKeychainItemRead,
            kSecACLAuthorizationEncrypt,
            kSecACLAuthorizationDelete,
            kSecACLAuthorizationKeychainItemModify,
            kSecACLAuthorizationKeychainItemDelete,
        ]
    } {
        create_acl(
            &access,
            Some(&applications),
            "Slice E unrelated access",
            authorization,
        )?;
    }
    create_acl(&access, None, &partition, unsafe {
        kSecACLAuthorizationPartitionID
    })?;
    Ok(access)
}

fn trusted_application(path: &Path) -> Result<CFType, &'static str> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| "unrelated-app-path")?;
    let mut application = ptr::null();
    let status =
        unsafe { SecTrustedApplicationCreateFromPath(path.as_ptr(), &raw mut application) };
    if status != 0 || application.is_null() {
        return Err("unrelated-app-create");
    }
    Ok(unsafe { CFType::wrap_under_create_rule(application) })
}

fn create_acl(
    access: &SecAccess,
    applications: Option<&CFArray<CFType>>,
    description: &str,
    authorization: CFStringRef,
) -> Result<(), &'static str> {
    let applications = applications.map_or(ptr::null(), |value| value.as_concrete_TypeRef());
    let description = CFString::new(description);
    let mut acl = ptr::null();
    let status = unsafe {
        SecACLCreateWithSimpleContents(
            access.as_concrete_TypeRef().cast(),
            applications,
            description.as_concrete_TypeRef(),
            0,
            &raw mut acl,
        )
    };
    if status != 0 || acl.is_null() {
        return Err("unrelated-acl-create");
    }
    let acl = unsafe { CFType::wrap_under_create_rule(acl) };
    let authorization = unsafe { CFString::wrap_under_get_rule(authorization) };
    let authorizations = CFArray::from_CFTypes(&[authorization]);
    (unsafe {
        SecACLUpdateAuthorizations(acl.as_CFTypeRef(), authorizations.as_concrete_TypeRef())
    } == 0)
        .then_some(())
        .ok_or("unrelated-acl-authorizations")
}

fn copy_partition_description(item: &SecKeychainItem) -> Result<String, &'static str> {
    let mut source = ptr::null_mut();
    if unsafe { SecKeychainItemCopyAccess(item.as_concrete_TypeRef().cast(), &raw mut source) } != 0
        || source.is_null()
    {
        return Err("unrelated-copy-initial-access");
    }
    let source = unsafe { SecAccess::wrap_under_create_rule(source.cast()) };
    let list = unsafe {
        SecAccessCopyMatchingACLList(
            source.as_concrete_TypeRef().cast(),
            kSecACLAuthorizationPartitionID.cast(),
        )
    };
    if list.is_null() {
        return Err("unrelated-partition-list");
    }
    let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(list) };
    let mut partition = None;
    for acl in list.iter() {
        let mut applications = ptr::null();
        let mut description = ptr::null();
        let mut prompt_selector = 0;
        let status = unsafe {
            SecACLCopyContents(
                acl.as_CFTypeRef(),
                &raw mut applications,
                &raw mut description,
                &raw mut prompt_selector,
            )
        };
        if status == 0 && applications.is_null() && !description.is_null() && prompt_selector == 0 {
            let description = unsafe { CFString::wrap_under_create_rule(description) }.to_string();
            if partition.replace(description).is_some() {
                return Err("unrelated-partition-duplicate");
            }
            continue;
        }
        release(applications);
        release(description);
        if status != ACL_NOT_SIMPLE {
            return Err("unrelated-partition-contents");
        }
    }
    partition.ok_or("unrelated-partition-missing")
}

fn release<T>(value: *const T) {
    if !value.is_null() {
        unsafe { CFRelease(value.cast()) };
    }
}

pub(super) fn assert_replacement_denied(
    item: &SecKeychainItem,
    access: &SecAccess,
) -> Result<&'static str, &'static str> {
    let status = unsafe {
        SecKeychainItemSetAccess(
            item.as_concrete_TypeRef().cast(),
            access.as_concrete_TypeRef().cast(),
        )
    };
    (status == INVALID_ACCESS_CREDENTIALS)
        .then_some("terminal-readback-after-set-access-credentials-denied-67700")
        .ok_or("unrelated-set-access-not-credentials-denied")
}
