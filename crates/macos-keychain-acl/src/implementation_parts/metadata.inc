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
