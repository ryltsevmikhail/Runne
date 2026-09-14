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
    let mut records = Vec::new();
    let mut default_owner_entries = 0;
    for acl in list.iter() {
        match copy_acl_record(&acl)? {
            AclRecord::Simple(contents) => {
                if contents.applications.is_some()
                    || !prompt_selector_is_unconditional(contents.prompt_selector)
                {
                    return Err(KeychainAclError::AccessDenied);
                }
                let description = contents
                    .description
                    .ok_or(KeychainAclError::AccessDenied)?;
                // macOS 27 saves populated items as a full partition record
                // plus a subset record, and decrypt enforcement requires the
                // reader to be present in EVERY stored record. The readback is
                // therefore conjunctive and homogeneous: every Simple record
                // must parse to exactly the same enrolled id set (duplicates
                // of a full record are allowed), while a record holding only
                // a subset, or any foreign id, is a hard rejection.
                records.push(parse_partition_ids(&description.to_string())?);
            }
            AclRecord::RootOwner(RootOwnerAcl::Default) => default_owner_entries += 1,
            AclRecord::RootOwner(RootOwnerAcl::ChangeAcl) => {
                return Err(KeychainAclError::AccessDenied);
            }
        }
    }
    if default_owner_entries > 1 {
        return Err(KeychainAclError::AccessDenied);
    }
    homogeneous_partition_ids(&records)
}

/// Reduces the per-record partition id sets conjunctively: every saved
/// Simple record must carry exactly the same id set, so a homogeneous
/// duplicate of the full record passes while a subset record, a foreign
/// id, or the absence of any Simple record is a hard rejection.
fn homogeneous_partition_ids(records: &[Vec<String>]) -> Result<Vec<String>, KeychainAclError> {
    let Some(first) = records.first() else {
        return Err(KeychainAclError::AccessDenied);
    };
    if records.iter().any(|record| record != first) {
        return Err(KeychainAclError::AccessDenied);
    }
    let mut ids = first.clone();
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(ids)
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
