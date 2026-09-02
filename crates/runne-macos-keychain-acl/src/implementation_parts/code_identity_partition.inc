const SIGNING_INFORMATION: u32 = 1 << 1;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoUnique: CFStringRef;

    fn SecCodeCopySigningInformation(
        code: security_framework_sys::code_signing::SecStaticCodeRef,
        flags: u32,
        information: *mut core_foundation::dictionary::CFDictionaryRef,
    ) -> OSStatus;
}

fn exact_code_partition_ids(
    writer: &Path,
    reader: &Path,
) -> Result<Vec<String>, KeychainAclError> {
    let writer = code_partition_id(writer)?;
    let reader = code_partition_id(reader)?;
    Ok(if writer == reader {
        vec![writer]
    } else {
        vec![writer, reader]
    })
}

fn code_partition_id(path: &Path) -> Result<String, KeychainAclError> {
    use security_framework::os::macos::code_signing::{Flags, SecStaticCode};

    let path = std::fs::canonicalize(path).map_err(|_| KeychainAclError::InvalidExecutable)?;
    let url = core_foundation::url::CFURL::from_path(&path, false)
        .ok_or(KeychainAclError::InvalidExecutable)?;
    let code = SecStaticCode::from_path(&url, Flags::NONE)
        .map_err(|_| KeychainAclError::InvalidExecutable)?;
    let validity = unsafe {
        security_framework_sys::code_signing::SecStaticCodeCheckValidity(
            code.as_concrete_TypeRef(),
            (Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS).bits(),
            ptr::null_mut(),
        )
    };
    if validity != errSecSuccess {
        return Err(KeychainAclError::InvalidExecutable);
    }
    let hash = copy_code_directory_hash(&code)?;
    let mut id = String::with_capacity(47);
    id.push_str("cdhash:");
    for byte in hash {
        use std::fmt::Write as _;
        write!(&mut id, "{byte:02x}").map_err(|_| KeychainAclError::OperationFailed)?;
    }
    Ok(id)
}

fn copy_code_directory_hash(
    code: &security_framework::os::macos::code_signing::SecStaticCode,
) -> Result<[u8; 20], KeychainAclError> {
    use core_foundation::base::{CFGetTypeID, TCFType as _};
    use core_foundation::data::{CFData, CFDataGetTypeID};
    use core_foundation::dictionary::{CFDictionary, CFDictionaryGetValue};

    let mut raw = ptr::null();
    let copy_status = unsafe {
        SecCodeCopySigningInformation(
            code.as_concrete_TypeRef(),
            SIGNING_INFORMATION,
            &raw mut raw,
        )
    };
    status(copy_status)?;
    if raw.is_null() {
        return Err(KeychainAclError::InvalidExecutable);
    }
    let information: CFDictionary = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    let value = unsafe {
        CFDictionaryGetValue(
            information.as_concrete_TypeRef(),
            kSecCodeInfoUnique.cast(),
        )
    };
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFDataGetTypeID() } {
        return Err(KeychainAclError::InvalidExecutable);
    }
    let hash = unsafe { CFData::wrap_under_get_rule(value.cast_mut().cast()) };
    hash.bytes()
        .try_into()
        .map_err(|_| KeychainAclError::InvalidExecutable)
}
