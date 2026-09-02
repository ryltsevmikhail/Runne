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
    let inspection = access_for_acl_inspection(&access)?;
    verify_access_profile(&inspection, expected_digest)?;
    if !verify_noncaller_owner(&access)? {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(())
}

/// Freshly verifies the exact writer/reader access created with the item.
///
/// The caller must be the already authenticated writer that created the item.
/// Finalization succeeds only after native readback proves the noncaller owner,
/// partition, decrypt, read and writer-only ACLs are exactly the expected sets.
///
/// # Errors
///
/// Returns a closed access error for any missing, broader or uncommitted ACL.
fn finalize_created_item_access(
    item: &SecKeychainItem,
    expected: &ExactKeychainAccess,
) -> Result<(), KeychainAclError> {
    let access = copy_item_access(item)?;
    let decrypt = verify_decrypt_access(&access)?;
    let writer_only = verify_writer_only_access(&access, expected.writer_digest)?;
    let partitions = copy_partition_ids(&access)?;
    if decrypt != expected.trusted_digest || !writer_only {
        return Err(KeychainAclError::AccessDenied);
    }
    if partitions == expected.partition_ids && verify_noncaller_owner(&access)? {
        return verify_item_access(item, expected.digest);
    }
    Err(KeychainAclError::AccessDenied)
}

fn copy_item_access(item: &SecKeychainItem) -> Result<SecAccess, KeychainAclError> {
    let mut access = ptr::null_mut();
    let access_status =
        unsafe { SecKeychainItemCopyAccess(item.as_concrete_TypeRef(), &raw mut access) };
    let access_owner = RetainedCfOutput::new(access);
    status(access_status)?;
    if access.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    access_owner.disarm();
    Ok(unsafe { SecAccess::wrap_under_create_rule(access) })
}

fn verify_access_profile(
    access: &SecAccess,
    expected_digest: [u8; 32],
) -> Result<(), KeychainAclError> {
    let trusted_digest = verify_decrypt_access(access)?;
    if verify_read_access(access)? != trusted_digest {
        return Err(KeychainAclError::AccessDenied);
    }
    let writer_digest = writer_access_digest(access)?;
    if !verify_writer_only_access(access, writer_digest)? {
        return Err(KeychainAclError::AccessDenied);
    }
    let partition_ids = copy_partition_ids(access)?;
    if access_profile_digest(trusted_digest, writer_digest, &partition_ids)? != expected_digest {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(())
}

fn verify_noncaller_owner(access: &SecAccess) -> Result<bool, KeychainAclError> {
    let mut user_id = libc::uid_t::MAX;
    let mut group_id = libc::gid_t::MAX;
    let mut owner_type = u32::MAX;
    let verify_owner_status = unsafe {
        SecAccessCopyOwnerAndACL(
            access.as_concrete_TypeRef(),
            &raw mut user_id,
            &raw mut group_id,
            &raw mut owner_type,
            ptr::null_mut(),
        )
    };
    status(verify_owner_status)?;
    Ok(unsafe { libc::geteuid() } != 0 && user_id == 0 && group_id == 0 && owner_type == 1)
}
