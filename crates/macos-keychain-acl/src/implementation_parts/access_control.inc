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
