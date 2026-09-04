use std::sync::Arc;

#[cfg(test)]
#[path = "native_record_tests.rs"]
mod record_tests;

use core_foundation::{
    base::{CFType, TCFType, ToVoid},
    boolean::CFBoolean,
    data::CFData,
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
        kSecClassGenericPassword, kSecReturnAttributes, kSecReturnData,
        kSecUseDataProtectionKeychain, kSecValueData,
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
    static kSecAttrGeneric: CFStringRef;
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

fn add_attributes(
    locator: &CredentialItemLocator,
    material: &[u8],
    revision: Option<[u8; 16]>,
) -> CFDictionary {
    let query = exact_query(locator);
    let mut attributes = unsafe { query.to_mutable() };
    let data = CFData::from_arc(Arc::new(Zeroizing::new(material.to_vec())));
    unsafe {
        attributes.add(&kSecValueData.to_void(), &data.to_void());
        if let Some(revision) = revision {
            let metadata = CFData::from_buffer(&revision);
            attributes.add(&kSecAttrGeneric.to_void(), &metadata.to_void());
        }
    }
    attributes.to_immutable()
}

pub(super) fn add(
    locator: &CredentialItemLocator,
    material: &[u8],
    revision: Option<[u8; 16]>,
) -> CredentialKeychainStatus {
    if revision == Some([0; 16]) {
        return CredentialKeychainStatus::AccessDenied;
    }
    let attributes = add_attributes(locator, material, revision);
    unsafe {
        map_keychain_write_status(SecItemAdd(
            attributes.as_concrete_TypeRef(),
            core::ptr::null_mut(),
        ))
    }
}

pub(super) fn read_record(
    locator: &CredentialItemLocator,
) -> Result<super::CredentialStoredRecord, CredentialKeychainStatus> {
    let query = exact_query(locator);
    let mut attributes = unsafe { query.to_mutable() };
    unsafe {
        attributes.add(
            &kSecReturnData.to_void(),
            &CFBoolean::true_value().to_void(),
        );
        attributes.add(
            &kSecReturnAttributes.to_void(),
            &CFBoolean::true_value().to_void(),
        );
    }
    let mut result: CFTypeRef = core::ptr::null_mut();
    let status = unsafe { SecItemCopyMatching(attributes.as_concrete_TypeRef(), &raw mut result) };
    let retained = (!result.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(result) });
    let mapped = map_keychain_read_result(status, !result.is_null());
    if mapped != CredentialKeychainStatus::Observed {
        return Err(mapped);
    }
    let dictionary = retained
        .and_then(CFType::downcast_into::<CFDictionary>)
        .ok_or(CredentialKeychainStatus::AccessDenied)?;
    decode_record(&dictionary)
}

fn decode_record(
    attributes: &CFDictionary,
) -> Result<super::CredentialStoredRecord, CredentialKeychainStatus> {
    let material = data_attribute(attributes, unsafe { kSecValueData })?
        .ok_or(CredentialKeychainStatus::AccessDenied)?;
    let material = runne_provider::CredentialMaterial::from_bytes(material.bytes().to_vec())
        .map_err(|_| CredentialKeychainStatus::AccessDenied)?;
    let source_revision = data_attribute(attributes, unsafe { kSecAttrGeneric })?
        .map(|data| {
            <[u8; 16]>::try_from(data.bytes()).map_err(|_| CredentialKeychainStatus::AccessDenied)
        })
        .transpose()?;
    if source_revision == Some([0; 16]) {
        return Err(CredentialKeychainStatus::AccessDenied);
    }
    Ok(super::CredentialStoredRecord {
        material,
        source_revision,
    })
}

fn data_attribute(
    attributes: &CFDictionary,
    key: CFStringRef,
) -> Result<Option<CFData>, CredentialKeychainStatus> {
    attributes
        .find(key.to_void())
        .map(|value| {
            let value = unsafe { CFType::wrap_under_get_rule((*value).cast()) };
            value
                .downcast_into::<CFData>()
                .ok_or(CredentialKeychainStatus::AccessDenied)
        })
        .transpose()
}

#[cfg(test)]
pub(super) fn read(locator: &CredentialItemLocator) -> Result<Vec<u8>, CredentialKeychainStatus> {
    let mut bytes = Vec::new();
    read_record(locator)?
        .material
        .consume(|value| bytes.extend_from_slice(value));
    Ok(bytes)
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
