fn copy_partition_ids(access: &SecAccess) -> Result<Vec<String>, KeychainAclError> {
    let list = unsafe {
        SecAccessCopyMatchingACLList(
            access.as_concrete_TypeRef(),
            kSecACLAuthorizationPartitionID.cast(),
        )
    };
    if list.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(list) };
    if !(1..=2).contains(&list.len()) {
        return Err(KeychainAclError::AccessDenied);
    }
    let expected_non_partition_entries = list.len() - 1;
    let mut partition = None;
    let mut non_partition_entries = 0;
    for acl in list.iter() {
        match copy_partition_description(&acl) {
            Ok((description, prompt_selector)) => {
                if partition.is_some() || !prompt_selector_is_unconditional(prompt_selector) {
                    return Err(KeychainAclError::AccessDenied);
                }
                partition = Some(parse_partition_ids(&description)?);
            }
            Err(KeychainAclError::AccessDenied | KeychainAclError::OperationFailed) => {
                non_partition_entries += 1;
            }
            Err(error) => return Err(error),
        }
    }
    if non_partition_entries != expected_non_partition_entries {
        return Err(KeychainAclError::AccessDenied);
    }
    let mut ids = partition.ok_or(KeychainAclError::AccessDenied)?;
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

#[cfg(feature = "local-native-enrollment-test")]
fn replace_creator_partition(
    access: &SecAccess,
    creator_id: &str,
    expected_ids: &[String],
) -> Result<(), KeychainAclError> {
    let list = unsafe {
        SecAccessCopyMatchingACLList(
            access.as_concrete_TypeRef(),
            kSecACLAuthorizationPartitionID.cast(),
        )
    };
    if list.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(list) };
    if !(1..=2).contains(&list.len()) {
        return Err(KeychainAclError::AccessDenied);
    }
    let expected_non_partition_entries = list.len() - 1;
    let mut partition_index = None;
    let mut non_partition_entries = 0;
    for (index, acl) in list.iter().enumerate() {
        match copy_partition_description(&acl) {
            Ok((description, prompt_selector)) => {
                if partition_index.is_some()
                    || !prompt_selector_is_unconditional(prompt_selector)
                    || parse_partition_ids(&description)? != [creator_id]
                {
                    return Err(KeychainAclError::AccessDenied);
                }
                partition_index = Some(index);
            }
            Err(KeychainAclError::AccessDenied | KeychainAclError::OperationFailed) => {
                non_partition_entries += 1;
            }
            Err(error) => return Err(error),
        }
    }
    if non_partition_entries != expected_non_partition_entries {
        return Err(KeychainAclError::AccessDenied);
    }
    let partition_index =
        isize::try_from(partition_index.ok_or(KeychainAclError::AccessDenied)?)
            .map_err(|_| KeychainAclError::AccessDenied)?;
    let acl = list
        .get(partition_index)
        .ok_or(KeychainAclError::AccessDenied)?;
    let description = CFString::new(&encode_partition_description(expected_ids)?);
    status(unsafe {
        SecACLSetContents(
            acl.as_CFTypeRef(),
            ptr::null(),
            description.as_concrete_TypeRef(),
            0,
        )
    })
}

fn copy_partition_description(acl: &CFType) -> Result<(String, u16), KeychainAclError> {
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
    status(copy_status)?;
    if !applications.is_null() || description.is_null() {
        return Err(KeychainAclError::AccessDenied);
    }
    drop(applications_owner);
    description_owner.disarm();
    let description = unsafe { CFString::wrap_under_create_rule(description) };
    Ok((description.to_string(), prompt_selector))
}

fn parse_partition_ids(description: &str) -> Result<Vec<String>, KeychainAclError> {
    let bytes = decode_hex(description)?;
    let xml = std::str::from_utf8(&bytes).map_err(|_| KeychainAclError::AccessDenied)?;
    let entries = xml
        .strip_prefix(PARTITION_PLIST_PREFIX)
        .and_then(|xml| xml.strip_suffix(PARTITION_PLIST_SUFFIX))
        .ok_or(KeychainAclError::AccessDenied)?;
    let mut ids = entries
        .lines()
        .map(|line| {
            line.strip_prefix("\t\t<string>")
                .and_then(|line| line.strip_suffix("</string>"))
                .map(str::to_ascii_lowercase)
                .ok_or(KeychainAclError::AccessDenied)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if ids.is_empty()
        || ids.iter().any(|id| {
            let Some(hash) = id.strip_prefix("cdhash:") else {
                return true;
            };
            hash.len() != 40 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(KeychainAclError::AccessDenied);
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

#[cfg(feature = "local-native-enrollment-test")]
fn encode_partition_description(ids: &[String]) -> Result<String, KeychainAclError> {
    if ids.is_empty() || ids.iter().any(|id| !valid_partition_id(id)) {
        return Err(KeychainAclError::AccessDenied);
    }
    let mut xml = String::from(PARTITION_PLIST_PREFIX);
    for id in ids {
        use std::fmt::Write as _;
        writeln!(&mut xml, "\t\t<string>{id}</string>")
            .map_err(|_| KeychainAclError::OperationFailed)?;
    }
    xml.push_str(PARTITION_PLIST_SUFFIX);
    Ok(encode_hex(xml.as_bytes()))
}

const PARTITION_PLIST_PREFIX: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\t<key>Partitions</key>\n\t<array>\n";
const PARTITION_PLIST_SUFFIX: &str = "\t</array>\n</dict>\n</plist>\n";

#[cfg(feature = "local-native-enrollment-test")]
fn valid_partition_id(id: &str) -> bool {
    id.strip_prefix("cdhash:").is_some_and(|hash| {
        hash.len() == 40 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn decode_hex(value: &str) -> Result<Vec<u8>, KeychainAclError> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(KeychainAclError::AccessDenied);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| KeychainAclError::AccessDenied)?;
            u8::from_str_radix(pair, 16).map_err(|_| KeychainAclError::AccessDenied)
        })
        .collect()
}

#[cfg(feature = "local-native-enrollment-test")]
fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String formatting cannot fail");
    }
    encoded
}

fn access_profile_digest(
    trusted_digest: [u8; 32],
    writer_digest: [u8; 32],
    partition_ids: &[String],
) -> Result<[u8; 32], KeychainAclError> {
    let mut partition_ids = partition_ids.to_vec();
    partition_ids.sort_unstable();
    partition_ids.dedup();
    if partition_ids.is_empty() {
        return Err(KeychainAclError::AccessDenied);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"runne-provider-credential-access-profile-v2\0");
    hasher.update(trusted_digest);
    hasher.update(writer_digest);
    hasher.update(
        u32::try_from(partition_ids.len())
            .map_err(|_| KeychainAclError::AccessDenied)?
            .to_be_bytes(),
    );
    for id in &partition_ids {
        hasher.update(
            u32::try_from(id.len())
                .map_err(|_| KeychainAclError::AccessDenied)?
                .to_be_bytes(),
        );
        hasher.update(id.as_bytes());
    }
    Ok(hasher.finalize().into())
}
