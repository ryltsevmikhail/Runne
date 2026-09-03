use std::sync::Arc;

use core_foundation::{
    base::{TCFType, ToVoid},
    boolean::CFBoolean,
    data::{CFData, CFDataRef},
    dictionary::{CFDictionary, CFMutableDictionary},
    string::CFString,
};
#[cfg(test)]
use core_foundation_sys::base::CFEqual;
use core_foundation_sys::base::CFTypeRef;
use core_foundation_sys::string::CFStringRef;
#[cfg(test)]
use security_framework_sys::item::{kSecAttrAccessControl, kSecMatchLimit, kSecUseKeychain};
use security_framework_sys::{
    access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    item::{
        kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecReturnData, kSecUseDataProtectionKeychain, kSecValueData,
    },
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete},
};
use zeroize::Zeroizing;

use super::{
    CredentialItemLocator, CredentialKeychainStatus, map_keychain_read_result,
    map_keychain_write_status,
};

unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
}

fn exact_query(locator: &CredentialItemLocator) -> CFDictionary {
    let mut query = CFMutableDictionary::from_CFType_pairs(&[]);
    let service = CFString::new(locator.service());
    let account = CFString::new(locator.account());
    let group = CFString::new(CredentialItemLocator::access_group());
    unsafe {
        query.add(&kSecClass.to_void(), &kSecClassGenericPassword.to_void());
        query.add(&kSecAttrService.to_void(), &service.to_void());
        query.add(&kSecAttrAccount.to_void(), &account.to_void());
        query.add(&kSecAttrAccessGroup.to_void(), &group.to_void());
        query.add(
            &kSecUseDataProtectionKeychain.to_void(),
            &CFBoolean::true_value().to_void(),
        );
        query.add(
            &kSecAttrSynchronizable.to_void(),
            &CFBoolean::false_value().to_void(),
        );
        query.add(
            &kSecAttrAccessible.to_void(),
            &kSecAttrAccessibleWhenUnlockedThisDeviceOnly.to_void(),
        );
    }
    query.to_immutable()
}

pub(super) fn add(locator: &CredentialItemLocator, material: &[u8]) -> CredentialKeychainStatus {
    let query = exact_query(locator);
    let mut attributes = unsafe { query.to_mutable() };
    let data = CFData::from_arc(Arc::new(Zeroizing::new(material.to_vec())));
    unsafe {
        attributes.add(&kSecValueData.to_void(), &data.to_void());
        map_keychain_write_status(SecItemAdd(
            attributes.as_concrete_TypeRef(),
            core::ptr::null_mut(),
        ))
    }
}

pub(super) fn read(locator: &CredentialItemLocator) -> Result<Vec<u8>, CredentialKeychainStatus> {
    let query = exact_query(locator);
    let mut attributes = unsafe { query.to_mutable() };
    unsafe {
        attributes.add(
            &kSecReturnData.to_void(),
            &CFBoolean::true_value().to_void(),
        );
    }
    let mut result: CFTypeRef = core::ptr::null_mut();
    let status = unsafe { SecItemCopyMatching(attributes.as_concrete_TypeRef(), &raw mut result) };
    let mapped = map_keychain_read_result(status, !result.is_null());
    if mapped != CredentialKeychainStatus::Observed {
        return Err(mapped);
    }
    let data = unsafe { CFData::wrap_under_create_rule(result.cast::<_>() as CFDataRef) };
    Ok(data.bytes().to_vec())
}

pub(super) fn delete(locator: &CredentialItemLocator) -> CredentialKeychainStatus {
    let query = exact_query(locator);
    map_keychain_write_status(unsafe { SecItemDelete(query.as_concrete_TypeRef()) })
}

#[cfg(test)]
pub(super) fn query_has_exact_policy(locator: &CredentialItemLocator) -> bool {
    let query = exact_query(locator);
    let service = CFString::new(locator.service());
    let account = CFString::new(locator.account());
    let group = CFString::new(CredentialItemLocator::access_group());
    unsafe {
        query.len() == 7
            && value_equals(&query, kSecClass, kSecClassGenericPassword.cast())
            && value_equals(&query, kSecAttrService, service.as_CFTypeRef())
            && value_equals(&query, kSecAttrAccount, account.as_CFTypeRef())
            && value_equals(&query, kSecAttrAccessGroup, group.as_CFTypeRef())
            && value_equals(
                &query,
                kSecUseDataProtectionKeychain,
                CFBoolean::true_value().as_CFTypeRef(),
            )
            && value_equals(
                &query,
                kSecAttrSynchronizable,
                CFBoolean::false_value().as_CFTypeRef(),
            )
            && value_equals(
                &query,
                kSecAttrAccessible,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly.cast(),
            )
            && !has_key(&query, kSecAttrAccessControl)
            && !has_key(&query, kSecUseKeychain)
            && !has_key(&query, kSecMatchLimit)
    }
}

#[cfg(test)]
unsafe fn value_equals(query: &CFDictionary, key: CFStringRef, expected: CFTypeRef) -> bool {
    query
        .find(key.to_void())
        .is_some_and(|actual| unsafe { CFEqual((*actual).cast(), expected) != 0 })
}

#[cfg(test)]
unsafe fn has_key(query: &CFDictionary, key: CFStringRef) -> bool {
    query.find(key.to_void()).is_some()
}
