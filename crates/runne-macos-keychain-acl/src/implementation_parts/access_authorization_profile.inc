fn verify_decrypt_access(access: &SecAccess) -> Result<[u8; 32], KeychainAclError> {
    application_acl_digest(access, unsafe { kSecACLAuthorizationDecrypt })
}

fn verify_read_access(access: &SecAccess) -> Result<[u8; 32], KeychainAclError> {
    application_acl_digest(access, unsafe { kSecACLAuthorizationKeychainItemRead })
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
    let mut owner_entries = 0;
    for acl in list.iter() {
        match copy_acl_contents(&acl) {
            Ok((applications, prompt_selector)) => {
                if !applications.is_empty()
                    || !prompt_selector_is_unconditional(prompt_selector)
                {
                    return Ok(false);
                }
                owner_entries += 1;
            }
            Err(KeychainAclError::AccessDenied | KeychainAclError::OperationFailed) => {
                owner_entries += 1;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(owner_entries <= 1 && (!require_owner || owner_entries == 1))
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
        match copy_acl_contents(&acl) {
            Ok((applications, prompt_selector)) => {
                if applications.is_empty() || !prompt_selector_is_unconditional(prompt_selector) {
                    return Err(KeychainAclError::AccessDenied);
                }
                digests.extend(
                    applications
                        .iter()
                        .map(|application| trusted_application_digest(application.as_CFTypeRef()))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            Err(KeychainAclError::AccessDenied | KeychainAclError::OperationFailed) => {
                owner_entries += 1;
            }
            Err(error) => return Err(error),
        }
    }
    if owner_entries > 1 {
        return Err(KeychainAclError::AccessDenied);
    }
    digest_set(digests)
}

fn application_acl_digest(
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
    let digests = list
        .iter()
        .map(|acl| -> Result<Vec<[u8; 32]>, KeychainAclError> {
            let (applications, prompt_selector) = copy_acl_contents(&acl)?;
            if !prompt_selector_is_unconditional(prompt_selector) {
                return Err(KeychainAclError::AccessDenied);
            }
            applications
                .iter()
                .map(|application| trusted_application_digest(application.as_CFTypeRef()))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
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
