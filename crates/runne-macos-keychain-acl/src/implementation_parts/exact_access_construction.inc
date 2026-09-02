fn create_exact_noncaller_access(
    writer: &CFType,
    reader: &CFType,
    partition_ids: &[String],
) -> Result<SecAccess, KeychainAclError> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(KeychainAclError::AccessDenied);
    }
    let access = create_noncaller_owner_template()?;
    let trusted = CFArray::from_CFTypes(&[writer.clone(), reader.clone()]);
    create_application_acl(
        &access,
        &trusted,
        unsafe { kSecACLAuthorizationDecrypt },
    )?;
    create_application_acl(
        &access,
        &trusted,
        unsafe { kSecACLAuthorizationKeychainItemRead },
    )?;

    let writer_only = CFArray::from_CFTypes(std::slice::from_ref(writer));
    for authorization in unsafe {
        [
            kSecACLAuthorizationEncrypt,
            kSecACLAuthorizationDelete,
            kSecACLAuthorizationKeychainItemModify,
            kSecACLAuthorizationKeychainItemDelete,
        ]
    } {
        create_application_acl(&access, &writer_only, authorization)?;
    }
    create_partition_acl(&access, partition_ids)?;
    Ok(access)
}

fn create_partition_acl(
    access: &SecAccess,
    partition_ids: &[String],
) -> Result<(), KeychainAclError> {
    let description = encode_partition_description(partition_ids)?;
    create_null_application_acl(
        access,
        &description,
        unsafe { kSecACLAuthorizationPartitionID },
    )
}

fn create_null_application_acl(
    access: &SecAccess,
    description: &str,
    authorization: CFStringRef,
) -> Result<(), KeychainAclError> {
    let description = CFString::new(description);
    let mut acl = ptr::null();
    status(unsafe {
        SecACLCreateWithSimpleContents(
            access.as_concrete_TypeRef(),
            ptr::null(),
            description.as_concrete_TypeRef(),
            0,
            &raw mut acl,
        )
    })?;
    if acl.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    let acl = unsafe { CFType::wrap_under_create_rule(acl) };
    let authorization = unsafe { CFString::wrap_under_get_rule(authorization) };
    let authorizations = CFArray::from_CFTypes(&[authorization]);
    status(unsafe {
        SecACLUpdateAuthorizations(
            acl.as_CFTypeRef(),
            authorizations.as_concrete_TypeRef(),
        )
    })
}
