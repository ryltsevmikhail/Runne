#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootOwnerAcl {
    Default,
    ChangeAcl,
}

struct SimpleAclContents {
    applications: Option<CFArray<CFType>>,
    description: Option<CFString>,
    prompt_selector: u16,
}

enum AclRecord {
    Simple(SimpleAclContents),
    RootOwner(RootOwnerAcl),
}

fn copy_acl_record(acl: &CFType) -> Result<AclRecord, KeychainAclError> {
    let mut applications = ptr::null();
    let mut description = ptr::null();
    let mut prompt_selector = 0;
    let copy_status = unsafe {
        SecACLCopyContents(
            acl.as_CFTypeRef(),
            &raw mut applications,
            &raw mut description,
            &raw mut prompt_selector,
        )
    };
    let applications_owner = RetainedCfOutput::new(applications);
    let description_owner = RetainedCfOutput::new(description);
    if copy_status == ERR_SEC_ACL_NOT_SIMPLE {
        if !applications.is_null() || !description.is_null() {
            return Err(KeychainAclError::AccessDenied);
        }
        return copy_root_owner_acl(acl).map(AclRecord::RootOwner);
    }
    status(copy_status)?;
    let applications = if applications.is_null() {
        None
    } else {
        applications_owner.disarm();
        Some(unsafe { CFArray::<CFType>::wrap_under_create_rule(applications) })
    };
    let description = if description.is_null() {
        None
    } else {
        description_owner.disarm();
        Some(unsafe { CFString::wrap_under_create_rule(description) })
    };
    Ok(AclRecord::Simple(SimpleAclContents {
        applications,
        description,
        prompt_selector,
    }))
}

fn copy_root_owner_acl(acl: &CFType) -> Result<RootOwnerAcl, KeychainAclError> {
    let authorizations = unsafe { SecACLCopyAuthorizations(acl.as_CFTypeRef()) };
    if authorizations.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    // SAFETY: the copy call returned a retained non-null array.
    let authorizations = unsafe { CFArray::<CFType>::wrap_under_create_rule(authorizations) };
    root_owner_acl_from_authorizations(&authorizations)
}

fn root_owner_acl_from_authorizations(
    authorizations: &CFArray<CFType>,
) -> Result<RootOwnerAcl, KeychainAclError> {
    if authorizations.is_empty() {
        return Ok(RootOwnerAcl::Default);
    }
    let any = unsafe { CFString::wrap_under_get_rule(kSecACLAuthorizationAny) };
    if authorizations.len() == 1
        && authorizations
            .get(0)
            .is_some_and(|value| *value == any.as_CFType())
    {
        // macOS 27 stores the saved no-applications owner record with its
        // authorizations normalized to the single `Any` entry.
        return Ok(RootOwnerAcl::Default);
    }
    let change_acl = unsafe { CFString::wrap_under_get_rule(kSecACLAuthorizationChangeACL) };
    if authorizations.len() == 1
        && authorizations
            .get(0)
            .is_some_and(|value| *value == change_acl.as_CFType())
    {
        return Ok(RootOwnerAcl::ChangeAcl);
    }
    Err(KeychainAclError::AccessDenied)
}

fn verify_root_owner_acl_shape(access: &SecAccess) -> Result<(), KeychainAclError> {
    let mut list = ptr::null();
    status(unsafe { SecAccessCopyACLList(access.as_concrete_TypeRef(), &raw mut list) })?;
    if list.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(list) };
    let mut default_owner = 0;
    let mut change_acl_owner = 0;
    for acl in list.iter() {
        match copy_acl_record(&acl)? {
            AclRecord::Simple(_) => {}
            AclRecord::RootOwner(RootOwnerAcl::Default) => default_owner += 1,
            AclRecord::RootOwner(RootOwnerAcl::ChangeAcl) => change_acl_owner += 1,
        }
    }
    if default_owner == 1 && change_acl_owner == 1 {
        Ok(())
    } else {
        Err(KeychainAclError::AccessDenied)
    }
}
