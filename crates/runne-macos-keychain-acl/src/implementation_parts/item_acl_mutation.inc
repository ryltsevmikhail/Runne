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
