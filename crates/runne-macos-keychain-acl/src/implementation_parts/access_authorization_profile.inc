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
    let mut empty_complex_entries = 0;
    let mut matching_complex_entries = 0;
    for acl in list.iter() {
        match copy_acl_contents(&acl) {
            Ok((applications, prompt_selector)) => {
                if !applications.is_empty()
                    || !prompt_selector_is_unconditional(prompt_selector)
                {
                    return Ok(false);
                }
                simple_owner_entries += 1;
            }
            Err(KeychainAclError::AccessDenied | KeychainAclError::OperationFailed) => {
                match complex_acl_authorizations(&acl, authorization)? {
                    ComplexAclAuthorizations::Empty => empty_complex_entries += 1,
                    ComplexAclAuthorizations::Matching => matching_complex_entries += 1,
                    ComplexAclAuthorizations::Other => return Ok(false),
                }
            }
            Err(error) => return Err(error),
        }
    }
    if require_owner {
        return Ok((simple_owner_entries == 1
            && empty_complex_entries == 0
            && matching_complex_entries == 0)
            || (simple_owner_entries == 0
                && empty_complex_entries == 1
                && matching_complex_entries == 1));
    }
    Ok(simple_owner_entries + empty_complex_entries + matching_complex_entries <= 1)
}

enum ComplexAclAuthorizations {
    Empty,
    Matching,
    Other,
}

fn complex_acl_authorizations(
    acl: &CFType,
    expected: CFStringRef,
) -> Result<ComplexAclAuthorizations, KeychainAclError> {
    let authorizations = unsafe { SecACLCopyAuthorizations(acl.as_CFTypeRef()) };
    if authorizations.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    let authorizations = unsafe { CFArray::<CFType>::wrap_under_create_rule(authorizations) };
    if authorizations.is_empty() {
        return Ok(ComplexAclAuthorizations::Empty);
    }
    let expected = unsafe { CFString::wrap_under_get_rule(expected) }.as_CFType();
    Ok(if authorizations.len() == 1
        && authorizations.get(0).is_some_and(|value| *value == expected)
    {
        ComplexAclAuthorizations::Matching
    } else {
        ComplexAclAuthorizations::Other
    })
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
