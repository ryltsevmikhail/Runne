#[cfg(test)]
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

/// Exact trusted-application decrypt access plus its canonical set digest.
pub struct ExactKeychainAccess {
    creation_access: SecAccess,
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
        let creation_access =
            create_exact_noncaller_access(&writer, &reader, &partition_ids)?;
        if verify_access_profile(&creation_access, digest).is_err()
            || !verify_noncaller_owner(&creation_access)?
        {
            return Err(KeychainAclError::AccessDenied);
        }
        Ok(Self {
            creation_access,
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

#[cfg(test)]
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

#[cfg(test)]
fn clone_acl_data_with_owner_using_cf_list(
    access: &SecAccess,
    user_id: libc::uid_t,
    group_id: libc::gid_t,
) -> Result<SecAccess, KeychainAclError> {
    let mut acl_list = ptr::null();
    status(unsafe {
        SecAccessCopyACLList(access.as_concrete_TypeRef(), &raw mut acl_list)
    })?;
    let acl_list_owner = RetainedCfOutput::new(acl_list);
    if acl_list.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    acl_list_owner.disarm();
    let acl_list = unsafe { CFArray::<CFType>::wrap_under_create_rule(acl_list) };
    if acl_list.is_empty() {
        return Err(KeychainAclError::AccessDenied);
    }
    let mut error = ptr::null();
    let cloned = unsafe {
        SecAccessCreateWithOwnerAndACL(
            user_id,
            group_id,
            1,
            acl_list.as_concrete_TypeRef(),
            &raw mut error,
        )
    };
    let error_owner = RetainedCfOutput::new(error);
    let cloned_owner = RetainedCfOutput::new(cloned);
    if cloned.is_null() || !error.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    drop(error_owner);
    cloned_owner.disarm();
    Ok(unsafe { SecAccess::wrap_under_create_rule(cloned) })
}
