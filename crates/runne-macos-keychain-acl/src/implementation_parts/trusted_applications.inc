fn trusted_application(path: &Path) -> Result<CFType, KeychainAclError> {
    let path = std::fs::canonicalize(path).map_err(|_| KeychainAclError::InvalidExecutable)?;
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| KeychainAclError::InvalidExecutable)?;
    let mut application = ptr::null();
    // SAFETY: `path` is NUL-terminated and alive, and `application` is a valid
    // writable out-pointer handled under the create rule below.
    let create_status =
        unsafe { SecTrustedApplicationCreateFromPath(path.as_ptr(), &raw mut application) };
    let application_owner = RetainedCfOutput::new(application);
    status(create_status)?;
    if application.is_null() {
        return Err(KeychainAclError::InvalidExecutable);
    }
    application_owner.disarm();
    // SAFETY: the create function returned a non-null retained CF object.
    Ok(unsafe { CFType::wrap_under_create_rule(application) })
}

fn trusted_application_set_digest(applications: &[&CFType]) -> Result<[u8; 32], KeychainAclError> {
    let digests = applications
        .iter()
        .map(|application| trusted_application_digest(application.as_CFTypeRef()))
        .collect::<Result<Vec<_>, _>>()?;
    digest_set(digests)
}

fn trusted_application_digest(application: CFTypeRef) -> Result<[u8; 32], KeychainAclError> {
    let mut data = ptr::null();
    // SAFETY: `application` is a live trusted-application CF object and `data`
    // is a valid writable out-pointer handled under the copy rule below.
    let copy_status = unsafe { SecTrustedApplicationCopyData(application, &raw mut data) };
    let data_owner = RetainedCfOutput::new(data);
    status(copy_status)?;
    if data.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    data_owner.disarm();
    // SAFETY: the Copy function returned a non-null retained CFData.
    let data = unsafe { CFData::wrap_under_create_rule(data) };
    if data.bytes().is_empty() {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(Sha256::digest(data.bytes()).into())
}

fn digest_set(mut digests: Vec<[u8; 32]>) -> Result<[u8; 32], KeychainAclError> {
    digests.sort_unstable();
    digests.dedup();
    if digests.is_empty() {
        return Err(KeychainAclError::AccessDenied);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"runne-provider-credential-acl-set-v1\0");
    hasher.update(
        u32::try_from(digests.len())
            .map_err(|_| KeychainAclError::AccessDenied)?
            .to_be_bytes(),
    );
    for digest in digests {
        hasher.update(digest);
    }
    Ok(hasher.finalize().into())
}

const fn status(code: OSStatus) -> Result<(), KeychainAclError> {
    if code == errSecSuccess {
        Ok(())
    } else if matches!(
        code,
        ERR_SEC_AUTH_FAILED
            | ERR_SEC_INTERACTION_NOT_ALLOWED
            | ERR_SEC_NO_ACCESS_FOR_ITEM
            | ERR_SEC_INVALID_OWNER_EDIT
    ) {
        Err(KeychainAclError::AccessDenied)
    } else {
        Err(KeychainAclError::OperationFailed)
    }
}

const fn prompt_selector_is_unconditional(prompt_selector: u16) -> bool {
    prompt_selector == 0
}
