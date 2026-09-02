fn verify_decrypt_access(access: &SecAccess) -> Result<[u8; 32], KeychainAclError> {
    application_acl_digest_with_owner(access, unsafe { kSecACLAuthorizationDecrypt })
}

fn verify_read_access(access: &SecAccess) -> Result<[u8; 32], KeychainAclError> {
    application_acl_digest_with_owner(access, unsafe { kSecACLAuthorizationKeychainItemRead })
}

fn verify_writer_only_access(
    access: &SecAccess,
    expected: [u8; 32],
) -> Result<bool, KeychainAclError> {
    Ok(writer_access_digest(access)? == expected && change_acl_is_owner_only(access)?)
}

fn writer_access_digest(access: &SecAccess) -> Result<[u8; 32], KeychainAclError> {
    let mut observed = None;
    for authorization in unsafe {
        [
            kSecACLAuthorizationEncrypt,
            kSecACLAuthorizationDelete,
            kSecACLAuthorizationKeychainItemModify,
            kSecACLAuthorizationKeychainItemDelete,
        ]
    } {
        let digest = application_acl_digest_with_owner(access, authorization)?;
        if observed.replace(digest).is_some_and(|prior| prior != digest) {
            return Err(KeychainAclError::AccessDenied);
        }
    }
    observed.ok_or(KeychainAclError::AccessDenied)
}

fn change_acl_is_owner_only(access: &SecAccess) -> Result<bool, KeychainAclError> {
    if !authorization_has_no_application_acl(access, unsafe { kSecACLAuthorizationAny }, false)? {
        return Ok(false);
    }
    if !authorization_has_no_application_acl(
        access,
        unsafe { kSecACLAuthorizationChangeOwner },
        false,
    )? {
        return Ok(false);
    }
    authorization_has_no_application_acl(
        access,
        unsafe { kSecACLAuthorizationChangeACL },
        true,
    )
}

fn authorization_has_no_application_acl(
    access: &SecAccess,
    authorization: CFStringRef,
    require_owner: bool,
) -> Result<bool, KeychainAclError> {
    let list = unsafe {
        SecAccessCopyMatchingACLList(access.as_concrete_TypeRef(), authorization.cast())
    };
    if list.is_null() {
        return Ok(!require_owner);
    }
    let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(list) };
    let mut simple_owner_entries = 0;
    let mut default_owner_entries = 0;
    let mut change_acl_owner_entries = 0;
    for acl in list.iter() {
        match copy_acl_record(&acl)? {
            AclRecord::Simple(contents) => {
                if contents
                    .applications
                    .as_ref()
                    .is_none_or(|applications| !applications.is_empty())
                    || !prompt_selector_is_unconditional(contents.prompt_selector)
                {
                    return Ok(false);
                }
                simple_owner_entries += 1;
            }
            AclRecord::RootOwner(RootOwnerAcl::Default) => default_owner_entries += 1,
            AclRecord::RootOwner(RootOwnerAcl::ChangeAcl) => change_acl_owner_entries += 1,
        }
    }
    if require_owner {
        return Ok((simple_owner_entries == 1
            && default_owner_entries == 0
            && change_acl_owner_entries == 0)
            || (simple_owner_entries == 0
                && default_owner_entries == 1
                && change_acl_owner_entries == 1));
    }
    Ok(change_acl_owner_entries == 0
        && ((simple_owner_entries == 0 && default_owner_entries <= 1)
            || (simple_owner_entries == 1 && default_owner_entries == 0)))
}

fn application_acl_digest_with_owner(
    access: &SecAccess,
    authorization: CFStringRef,
) -> Result<[u8; 32], KeychainAclError> {
    let list = unsafe {
        SecAccessCopyMatchingACLList(access.as_concrete_TypeRef(), authorization.cast())
    };
    if list.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(list) };
    let mut owner_entries = 0;
    let mut digests = Vec::new();
    for acl in list.iter() {
        match copy_acl_record(&acl)? {
            AclRecord::Simple(contents) => {
                let applications = contents
                    .applications
                    .ok_or(KeychainAclError::AccessDenied)?;
                if applications.is_empty()
                    || !prompt_selector_is_unconditional(contents.prompt_selector)
                {
                    return Err(KeychainAclError::AccessDenied);
                }
                digests.extend(
                    applications
                        .iter()
                        .map(|application| trusted_application_digest(application.as_CFTypeRef()))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            AclRecord::RootOwner(RootOwnerAcl::Default) => owner_entries += 1,
            AclRecord::RootOwner(RootOwnerAcl::ChangeAcl) => {
                return Err(KeychainAclError::AccessDenied);
            }
        }
    }
    if owner_entries > 1 {
        return Err(KeychainAclError::AccessDenied);
    }
    digest_set(digests)
}

fn create_application_acl(
    access: &SecAccess,
    applications: &CFArray<CFType>,
    authorization: CFStringRef,
) -> Result<(), KeychainAclError> {
    let description = CFString::new(ACL_DESCRIPTOR);
    let mut acl = ptr::null();
    status(unsafe {
        SecACLCreateWithSimpleContents(
            access.as_concrete_TypeRef(),
            applications.as_concrete_TypeRef(),
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
