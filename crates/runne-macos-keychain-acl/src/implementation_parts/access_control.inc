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
    #[cfg(any(test, not(feature = "local-native-enrollment-test")))]
    creation_access: SecAccess,
    #[cfg(any(test, feature = "local-native-enrollment-test"))]
    acl_source_access: SecAccess,
    digest: [u8; 32],
    trusted_digest: [u8; 32],
    writer_digest: [u8; 32],
    partition_ids: Vec<String>,
}

impl ExactKeychainAccess {
    /// Creates an access object containing only the canonical writer and reader.
    ///
    /// # Errors
    ///
    /// Returns a closed error when either trusted application or the access
    /// object cannot be created.
    pub fn new(writer_path: &Path, reader_path: &Path) -> Result<Self, KeychainAclError> {
        let writer = trusted_application(writer_path)?;
        let reader = trusted_application(reader_path)?;
        let writer_digest = trusted_application_set_digest(&[&writer])?;
        let trusted_digest = trusted_application_set_digest(&[&writer, &reader])?;
        let partition_ids = exact_code_partition_ids(writer_path, reader_path)?;
        let digest = access_profile_digest(trusted_digest, writer_digest, &partition_ids)?;
        let acl_source_access = create_exact_application_access(&writer, &reader)?;
        if verify_decrypt_access(&acl_source_access)? != trusted_digest
            || verify_read_access(&acl_source_access)? != trusted_digest
            || !verify_writer_only_access(&acl_source_access, writer_digest)?
        {
            return Err(KeychainAclError::AccessDenied);
        }
        let creation_access = access_with_noncaller_owner(&acl_source_access)?;
        if !verify_noncaller_owner(&creation_access)? {
            return Err(KeychainAclError::AccessDenied);
        }
        Ok(Self {
            #[cfg(any(test, not(feature = "local-native-enrollment-test")))]
            creation_access,
            #[cfg(any(test, feature = "local-native-enrollment-test"))]
            acl_source_access,
            digest,
            trusted_digest,
            writer_digest,
            partition_ids,
        })
    }

    /// Returns the non-secret canonical trusted-application set digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn create_exact_application_access(
    writer: &CFType,
    reader: &CFType,
) -> Result<SecAccess, KeychainAclError> {
    let trusted_list = CFArray::from_CFTypes(&[writer.clone(), reader.clone()]);
    let descriptor = CFString::new(ACL_DESCRIPTOR);
    let mut access = ptr::null_mut();
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
    let access = unsafe { SecAccess::wrap_under_create_rule(access) };
    create_application_acl(
        &access,
        &trusted_list,
        unsafe { kSecACLAuthorizationKeychainItemRead },
    )?;
    let writer_applications = CFArray::from_CFTypes(std::slice::from_ref(writer));
    for authorization in unsafe {
        [
            kSecACLAuthorizationEncrypt,
            kSecACLAuthorizationDelete,
            kSecACLAuthorizationKeychainItemModify,
            kSecACLAuthorizationKeychainItemDelete,
        ]
    } {
        create_application_acl(&access, &writer_applications, authorization)?;
    }
    Ok(access)
}

fn create_noncaller_owner_template() -> Result<SecAccess, KeychainAclError> {
    let mut error = ptr::null();
    let access = unsafe { SecAccessCreateWithOwnerAndACL(0, 0, 1, ptr::null(), &raw mut error) };
    let error_owner = RetainedCfOutput::new(error);
    if access.is_null() || !error.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    drop(error_owner);
    Ok(unsafe { SecAccess::wrap_under_create_rule(access) })
}

fn create_current_owner_template() -> Result<SecAccess, KeychainAclError> {
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
    let error_owner = RetainedCfOutput::new(error);
    if access.is_null() || !error.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    drop(error_owner);
    Ok(unsafe { SecAccess::wrap_under_create_rule(access) })
}

fn clone_acl_data_with_owner(
    access: &SecAccess,
    owner_template: &SecAccess,
) -> Result<SecAccess, KeychainAclError> {
    let mut owner = ptr::null_mut();
    let mut unused_owner_acl_count = 0;
    let mut unused_owner_acls = ptr::null_mut();
    status(unsafe {
        SecAccessGetOwnerAndACL(
            owner_template.as_concrete_TypeRef(),
            &raw mut owner,
            &raw mut unused_owner_acl_count,
            &raw mut unused_owner_acls,
        )
    })?;
    let mut unused_source_owner = ptr::null_mut();
    let mut acl_count = 0;
    let mut acls = ptr::null_mut();
    status(unsafe {
        SecAccessGetOwnerAndACL(
            access.as_concrete_TypeRef(),
            &raw mut unused_source_owner,
            &raw mut acl_count,
            &raw mut acls,
        )
    })?;
    if owner.is_null() || acl_count == 0 || acls.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    let mut cloned = ptr::null_mut();
    status(unsafe { SecAccessCreateFromOwnerAndACL(owner, acl_count, acls, &raw mut cloned) })?;
    if cloned.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(unsafe { SecAccess::wrap_under_create_rule(cloned) })
}

fn access_with_noncaller_owner(access: &SecAccess) -> Result<SecAccess, KeychainAclError> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(KeychainAclError::AccessDenied);
    }
    let owner_template = create_noncaller_owner_template()?;
    clone_acl_data_with_owner(access, &owner_template)
}

fn access_for_acl_inspection(access: &SecAccess) -> Result<SecAccess, KeychainAclError> {
    let owner_template = create_current_owner_template()?;
    clone_acl_data_with_owner(access, &owner_template)
}
