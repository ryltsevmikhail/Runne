/// Opaque native Keychain reference used only by the local feasibility probe.
pub struct PersistentKeychainReference(zeroize::Zeroizing<Vec<u8>>);

/// Holds the same process and UI exclusions as the native credential writer.
pub struct PersistentReferenceKeychainGuard {
    _process: ProviderCredentialProcessLock,
    _interaction: KeychainUserInteractionLock,
}

type ReferenceMetadata = Vec<(u32, Vec<u8>)>;

impl PersistentKeychainReference {
    /// Moves the bounded opaque reference to an owned inherited test channel.
    #[must_use]
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }
}

/// Opens only the caller-supplied disposable Keychain with Keychain UI disabled.
///
/// # Errors
///
/// Returns a closed error when the process exclusion, UI guard or exact
/// caller-supplied Keychain cannot be acquired.
pub fn open_noninteractive_keychain(
    path: &Path,
) -> Result<(PersistentReferenceKeychainGuard, SecKeychain), KeychainAclError> {
    let process = ProviderCredentialProcessLock::acquire()?;
    let interaction = SecKeychain::disable_user_interaction().map_err(|_| KeychainAclError::OperationFailed)?;
    let keychain = SecKeychain::open(path).map_err(|_| KeychainAclError::OperationFailed)?;
    Ok((PersistentReferenceKeychainGuard {
        _process: process,
        _interaction: interaction,
    }, keychain))
}

/// Reports only the native status from test-only material population.
///
/// # Errors
///
/// Returns the `Security.framework` status without copying credential bytes.
pub fn set_item_password_with_status(item: &mut SecKeychainItem, password: &[u8]) -> Result<(), i32> {
    item.set_password(password)
        .map_err(security_framework::base::Error::code)
}

/// Creates the Apple-supported bounded reference for an already finalized item.
///
/// # Errors
///
/// Returns a closed error if the reference cannot be created or is outside the
/// bounded opaque representation accepted by this native-only probe.
pub fn create_persistent_reference(
    item: &SecKeychainItem,
) -> Result<PersistentKeychainReference, KeychainAclError> {
    let mut reference: CFDataRef = ptr::null();
    // SAFETY: the item is live and the out-pointer receives one retained CFData.
    status(unsafe {
        SecKeychainItemCreatePersistentReference(item.as_concrete_TypeRef(), &raw mut reference)
    })?;
    if reference.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    // SAFETY: the Security.framework create call returned a retained CFData.
    let native = unsafe { CFData::wrap_under_create_rule(reference) };
    let native = native.bytes();
    if native.is_empty() || native.len() > 1024 {
        return Err(KeychainAclError::InvalidItemIdentity);
    }
    Ok(PersistentKeychainReference(zeroizing_copy(native)?))
}

/// Resolves exactly one opaque reference without any Keychain search operation.
///
/// # Errors
///
/// Returns a closed error for an empty, oversized, stale or unauthorized
/// reference, or if `Security.framework` does not return an item.
pub fn resolve_persistent_reference(reference: &[u8]) -> Result<SecKeychainItem, KeychainAclError> {
    if reference.is_empty() || reference.len() > 1024 {
        return Err(KeychainAclError::InvalidItemIdentity);
    }
    let reference = CFData::from_buffer(reference);
    let mut item = ptr::null_mut();
    // SAFETY: reference is live and `item` is a valid retained item out-pointer.
    status(unsafe {
        SecKeychainItemCopyFromPersistentReference(reference.as_concrete_TypeRef(), &raw mut item)
    })?;
    if item.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    // SAFETY: the Security.framework copy call returned a retained item.
    Ok(unsafe { SecKeychainItem::wrap_under_create_rule(item) })
}

/// Revalidates target Keychain, non-secret identity metadata and exact ACL.
///
/// # Errors
///
/// Returns a closed error if any target identity or complete access-profile
/// property differs from the caller's expected values.
pub fn verify_persistent_reference_item(
    item: &SecKeychainItem,
    expected_keychain: &SecKeychain,
    service: &str,
    account: &str,
    metadata: &[u8],
    access_digest: [u8; 32],
) -> Result<(), KeychainAclError> {
    if service.is_empty() || account.is_empty() || metadata.is_empty() {
        return Err(KeychainAclError::InvalidItemIdentity);
    }
    let mut keychain = ptr::null_mut();
    // SAFETY: item is live and the out-pointer receives a retained Keychain.
    status(unsafe { SecKeychainItemCopyKeychain(item.as_concrete_TypeRef(), &raw mut keychain) })?;
    if keychain.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    // SAFETY: the Security.framework copy call returned a retained Keychain.
    let keychain = unsafe { SecKeychain::wrap_under_create_rule(keychain) };
    if keychain != *expected_keychain {
        return Err(KeychainAclError::AccessDenied);
    }
    let (class, values) = copy_reference_metadata(item)?;
    if class != GENERIC_PASSWORD_ITEM_CLASS
        || values != [
            (SERVICE_ITEM_ATTRIBUTE, service.as_bytes().to_vec()),
            (ACCOUNT_ITEM_ATTRIBUTE, account.as_bytes().to_vec()),
            (GENERIC_ITEM_ATTRIBUTE, metadata.to_vec()),
        ]
    {
        return Err(KeychainAclError::AccessDenied);
    }
    verify_item_access(item, access_digest)
}

/// Copies the password only after the caller has completed item verification.
///
/// # Errors
///
/// Returns a closed error if `Security.framework` declines the read, returns an
/// unexpected item class, or cannot free the returned buffer.
pub fn copy_persistent_reference_password(
    item: &SecKeychainItem,
) -> Result<zeroize::Zeroizing<Vec<u8>>, KeychainAclError> {
    let mut class = 0_u32;
    let mut length = 0_u32;
    let mut data = ptr::null_mut();
    // SAFETY: item is live and only the password out-buffer is requested.
    let copy = unsafe {
        SecKeychainItemCopyContent(
            item.as_concrete_TypeRef(),
            &raw mut class,
            ptr::null_mut(),
            &raw mut length,
            &raw mut data,
        )
    };
    let result = if copy == errSecSuccess && !data.is_null() && length != 0 {
        // SAFETY: Security.framework allocated exactly `length` password bytes.
        let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length as usize) };
        zeroizing_copy(bytes)
    } else {
        Err(KeychainAclError::AccessDenied)
    };
    let cleanup = if data.is_null() {
        Ok(())
    } else {
        // SAFETY: this frees only the output allocated by CopyContent above.
        status(unsafe { SecKeychainItemFreeContent(ptr::null_mut(), data) })
    };
    cleanup?;
    if class != GENERIC_PASSWORD_ITEM_CLASS {
        return Err(KeychainAclError::AccessDenied);
    }
    result
}

fn zeroizing_copy(bytes: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, KeychainAclError> {
    let mut copy = zeroize::Zeroizing::new(Vec::new());
    copy.try_reserve(bytes.len())
        .map_err(|_| KeychainAclError::OperationFailed)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

#[cfg(test)]
#[test]
fn opaque_copy_allocates_only_after_its_zeroizing_owner_exists() {
    let copied = zeroizing_copy(&[7, 8, 9]).expect("bounded test copy");
    assert_eq!(copied.as_slice(), &[7, 8, 9]);
}

fn copy_reference_metadata(
    item: &SecKeychainItem,
) -> Result<(u32, ReferenceMetadata), KeychainAclError> {
    let mut attributes = [
        SecKeychainAttribute { tag: SERVICE_ITEM_ATTRIBUTE, length: 0, data: ptr::null_mut() },
        SecKeychainAttribute { tag: ACCOUNT_ITEM_ATTRIBUTE, length: 0, data: ptr::null_mut() },
        SecKeychainAttribute { tag: GENERIC_ITEM_ATTRIBUTE, length: 0, data: ptr::null_mut() },
    ];
    let mut list = SecKeychainAttributeList { count: 3, attr: attributes.as_mut_ptr() };
    let mut class = 0_u32;
    // SAFETY: item and attribute list stay live; password outputs are NULL.
    let copy = unsafe {
        SecKeychainItemCopyContent(
            item.as_concrete_TypeRef(),
            &raw mut class,
            &raw mut list,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let values = if copy == errSecSuccess {
        attributes
            .iter()
            .map(|attribute| {
                if attribute.data.is_null() {
                    return Err(KeychainAclError::AccessDenied);
                }
                // SAFETY: Security.framework returned `length` attribute bytes.
                Ok((attribute.tag, unsafe {
                    std::slice::from_raw_parts(attribute.data.cast::<u8>(), attribute.length as usize)
                }.to_vec()))
            })
            .collect()
    } else {
        Err(KeychainAclError::AccessDenied)
    };
    let should_free = copy == errSecSuccess
        || attributes
            .iter()
            .any(|attribute| attribute.length != 0 || !attribute.data.is_null());
    if should_free {
        // SAFETY: one or more outputs above may own Security.framework buffers.
        status(unsafe { SecKeychainItemFreeContent(&raw mut list, ptr::null_mut()) })?;
    }
    values.map(|values| (class, values))
}
