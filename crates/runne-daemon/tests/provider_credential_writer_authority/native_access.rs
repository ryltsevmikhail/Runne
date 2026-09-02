use std::ffi::c_void;
use std::ptr;

use core_foundation::array::CFArrayRef;
use core_foundation::base::TCFType as _;
use core_foundation::string::{CFString, CFStringRef};
use security_framework::os::macos::access::SecAccess;
use security_framework::os::macos::keychain_item::SecKeychainItem;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecAccessCreate(
        descriptor: CFStringRef,
        trusted_list: CFArrayRef,
        access: *mut *mut c_void,
    ) -> i32;
    fn SecAccessCreateFromOwnerAndACL(
        owner: *mut c_void,
        acl_count: u32,
        acls: *mut c_void,
        access: *mut *mut c_void,
    ) -> i32;
    fn SecAccessGetOwnerAndACL(
        access: *mut c_void,
        owner: *mut *mut c_void,
        acl_count: *mut u32,
        acls: *mut *mut c_void,
    ) -> i32;
    fn SecKeychainItemCopyAccess(item: *mut c_void, access: *mut *mut c_void) -> i32;
    fn SecKeychainItemSetAccess(item: *mut c_void, access: *mut c_void) -> i32;
}

pub(super) fn complex_attacker_access(item: &SecKeychainItem) -> Result<SecAccess, &'static str> {
    let mut source = ptr::null_mut();
    if unsafe { SecKeychainItemCopyAccess(item.as_concrete_TypeRef().cast(), &raw mut source) } != 0
        || source.is_null()
    {
        return Err("unrelated-copy-initial-access");
    }
    let source = unsafe { SecAccess::wrap_under_create_rule(source.cast()) };
    let descriptor = CFString::new("Slice E unrelated access");
    let mut owner_template = ptr::null_mut();
    if unsafe {
        SecAccessCreate(
            descriptor.as_concrete_TypeRef(),
            ptr::null(),
            &raw mut owner_template,
        )
    } != 0
        || owner_template.is_null()
    {
        return Err("unrelated-access-create");
    }
    let owner_template = unsafe { SecAccess::wrap_under_create_rule(owner_template.cast()) };
    let mut owner = ptr::null_mut();
    let mut unused_owner_acl_count = 0;
    let mut unused_owner_acls = ptr::null_mut();
    if unsafe {
        SecAccessGetOwnerAndACL(
            owner_template.as_concrete_TypeRef().cast(),
            &raw mut owner,
            &raw mut unused_owner_acl_count,
            &raw mut unused_owner_acls,
        )
    } != 0
        || owner.is_null()
    {
        return Err("unrelated-access-owner");
    }
    let mut unused_source_owner = ptr::null_mut();
    let mut acl_count = 0;
    let mut acls = ptr::null_mut();
    if unsafe {
        SecAccessGetOwnerAndACL(
            source.as_concrete_TypeRef().cast(),
            &raw mut unused_source_owner,
            &raw mut acl_count,
            &raw mut acls,
        )
    } != 0
        || acl_count == 0
        || acls.is_null()
    {
        return Err("unrelated-access-acls");
    }
    let mut cloned = ptr::null_mut();
    if unsafe { SecAccessCreateFromOwnerAndACL(owner, acl_count, acls, &raw mut cloned) } != 0
        || cloned.is_null()
    {
        return Err("unrelated-access-clone");
    }
    Ok(unsafe { SecAccess::wrap_under_create_rule(cloned.cast()) })
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
    match status {
        -67_700 => Ok("terminal-readback-after-set-access-credentials-denied-67700"),
        -25_240 => Err("unrelated-set-access-acl-not-simple-25240"),
        -67_701 => Err("unrelated-set-access-invalid-record-67701"),
        _ => Err("unrelated-set-access"),
    }
}
