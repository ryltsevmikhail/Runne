fn darwin_user_cache_directory() -> Result<CString, KeychainAclError> {
    // SAFETY: a NULL/zero probe is the documented confstr size query.
    let required = unsafe { libc::confstr(DARWIN_USER_CACHE_DIRECTORY, ptr::null_mut(), 0) };
    if required < 2 {
        return Err(KeychainAclError::OperationFailed);
    }
    let mut bytes = vec![0_u8; required];
    // SAFETY: buffer is writable for exactly `required` bytes.
    let written = unsafe {
        libc::confstr(
            DARWIN_USER_CACHE_DIRECTORY,
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if written != required {
        return Err(KeychainAclError::OperationFailed);
    }
    CString::from_vec_with_nul(bytes).map_err(|_| KeychainAclError::OperationFailed)
}

fn open_validated_directory(path: &CString) -> Result<File, KeychainAclError> {
    // SAFETY: path is NUL-terminated. O_NOFOLLOW rejects a symlink final
    // component; the Darwin cache path itself comes from confstr, not env.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(KeychainAclError::OperationFailed);
    }
    // SAFETY: open returned a new owned descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    validate_owner_only_directory(&directory)?;
    Ok(directory)
}

fn validate_owner_only_directory(directory: &File) -> Result<libc::stat, KeychainAclError> {
    // SAFETY: zeroed stat is valid output storage for fstat.
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: directory fd is live and metadata is a valid out-pointer.
    if unsafe { libc::fstat(directory.as_raw_fd(), &raw mut metadata) } != 0 {
        return Err(KeychainAclError::OperationFailed);
    }
    // SAFETY: geteuid has no preconditions.
    let current_uid = unsafe { libc::geteuid() };
    if metadata.st_uid != current_uid
        || metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_mode & 0o077 != 0
        || metadata.st_nlink == 0
    {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(metadata)
}

fn validate_directory_entry(
    parent_fd: libc::c_int,
    name: &CStr,
    directory: &File,
) -> Result<(), KeychainAclError> {
    let opened = validate_owner_only_directory(directory)?;
    // SAFETY: zeroed stat is valid output storage for fstatat.
    let mut linked = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: parent fd, NUL-terminated relative name and output are valid.
    if unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            &raw mut linked,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(KeychainAclError::AccessDenied);
    }
    if linked.st_dev != opened.st_dev
        || linked.st_ino != opened.st_ino
        || linked.st_uid != opened.st_uid
        || linked.st_mode & libc::S_IFMT != libc::S_IFDIR
        || linked.st_mode & 0o077 != 0
    {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(())
}

/// Creates an empty generic-password item atomically under the exact ACL.
///
/// Credential bytes are intentionally absent from this API and MUST NOT be
/// added later with `SecKeychainItemModifyAttributesAndData`: on macOS 27 the
/// first data or metadata modification of a saved item erases its partition
/// ACL record irreversibly. Callers that need the bytes stored must use
/// [`create_populated_generic_password`], which writes them in the same
/// creation step and keeps the verify-or-delete ordering intact. The empty
/// variant exists only for legacy incomplete-item recovery and test fixtures
/// whose items never receive material afterwards.
///
/// # Errors
///
/// Returns a closed error when the item identity is invalid or Keychain cannot
/// create the empty item with the supplied initial access.
pub fn create_empty_generic_password(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
    metadata: &[u8],
    exact: &ExactKeychainAccess,
) -> Result<CreatedGenericPasswordItem, KeychainAclError> {
    create_generic_password_content_with_access(keychain, service, account, metadata, None, &exact.creation_access)
}

/// Creates one generic-password item atomically under the exact ACL with the
/// credential bytes already stored.
///
/// The bytes and the final metadata travel in the single
/// `SecKeychainItemCreateFromContent` call, so no later modification can erase
/// the partition ACL (macOS 27 normalizes the ACL on the first
/// `SecKeychainItemModifyAttributesAndData`). The caller must immediately
/// [`CreatedGenericPasswordItem::finalize`] the saved item: that readback
/// verifies the full partition and owner ACL and deletes the item on any
/// failure, so credential material never persists unverified.
///
/// # Errors
///
/// Returns a closed error when the item identity is invalid or Keychain cannot
/// create the populated item with the supplied initial access.
pub fn create_populated_generic_password(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
    metadata: &[u8],
    password: &[u8],
    exact: &ExactKeychainAccess,
) -> Result<CreatedGenericPasswordItem, KeychainAclError> {
    create_generic_password_content_with_access(
        keychain,
        service,
        account,
        metadata,
        Some(password),
        &exact.creation_access,
    )
}

fn create_generic_password_content_with_access(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
    metadata: &[u8],
    password: Option<&[u8]>,
    access: &SecAccess,
) -> Result<CreatedGenericPasswordItem, KeychainAclError> {
    if service.is_empty()
        || account.is_empty()
        || service.as_bytes().contains(&0)
        || account.as_bytes().contains(&0)
        || metadata.is_empty()
    {
        return Err(KeychainAclError::InvalidItemIdentity);
    }
    let service_length =
        u32::try_from(service.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?;
    let account_length =
        u32::try_from(account.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?;
    let metadata_length =
        u32::try_from(metadata.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?;
    let mut attributes = [
        SecKeychainAttribute {
            tag: SERVICE_ITEM_ATTRIBUTE,
            length: service_length,
            data: service.as_ptr().cast_mut().cast(),
        },
        SecKeychainAttribute {
            tag: ACCOUNT_ITEM_ATTRIBUTE,
            length: account_length,
            data: account.as_ptr().cast_mut().cast(),
        },
        SecKeychainAttribute {
            tag: GENERIC_ITEM_ATTRIBUTE,
            length: metadata_length,
            data: metadata.as_ptr().cast_mut().cast(),
        },
    ];
    let mut attribute_list = SecKeychainAttributeList {
        count: u32::try_from(attributes.len())
            .map_err(|_| KeychainAclError::InvalidItemIdentity)?,
        attr: attributes.as_mut_ptr(),
    };
    let (password_length, password_data) = match password {
        Some(password) => (
            u32::try_from(password.len()).map_err(|_| KeychainAclError::InvalidItemIdentity)?,
            password.as_ptr().cast(),
        ),
        None => (0, ptr::null()),
    };
    let mut item = ptr::null_mut();
    // SAFETY: attribute buffers, the optional password buffer and all
    // Security.framework objects remain live for the call, and `item` is a
    // valid writable out-pointer consumed under the create rule below.
    let initial_access = access;
    let create_status = unsafe {
        SecKeychainItemCreateFromContent(
            GENERIC_PASSWORD_ITEM_CLASS,
            &raw mut attribute_list,
            password_length,
            password_data,
            keychain.as_concrete_TypeRef().cast(),
            initial_access.as_concrete_TypeRef(),
            &raw mut item,
        )
    };
    let item_owner = RetainedCfOutput::new(item);
    status(create_status)?;
    if item.is_null() {
        return Err(KeychainAclError::OperationFailed);
    }
    item_owner.disarm();
    // SAFETY: the create function returned a non-null retained item reference.
    Ok(CreatedGenericPasswordItem {
        item: unsafe { SecKeychainItem::wrap_under_create_rule(item) },
    })
}

/// A just-created item whose initial ACL still requires fresh readback.
pub struct CreatedGenericPasswordItem {
    item: SecKeychainItem,
}

impl CreatedGenericPasswordItem {
    /// Verifies the exact final ACL on the saved item.
    ///
    /// A failed verification deletes the saved item before returning, so
    /// credential material never persists without the proven partition ACL.
    ///
    /// # Errors
    ///
    /// Returns a closed error if exact ACL finalization or cleanup fails.
    pub fn finalize(
        self,
        exact: &ExactKeychainAccess,
    ) -> Result<SecKeychainItem, KeychainAclError> {
        if let Err(error) = finalize_created_item_access(&self.item, exact) {
            return if delete_item(&self.item).is_ok() {
                Err(error)
            } else {
                Err(KeychainAclError::OperationFailed)
            };
        }
        Ok(self.item)
    }

    /// Deletes an incomplete empty item.
    ///
    /// # Errors
    ///
    /// Returns a closed error if native deletion fails.
    pub fn delete(self) -> Result<(), KeychainAclError> {
        delete_item(&self.item)
    }
}

/// Non-secret generic attribute and item reference for one exact password item.
pub struct GenericPasswordMetadata {
    /// Caller-defined non-secret metadata bytes.
    pub bytes: Vec<u8>,
    /// Exact native item reference used for ACL verification and lifecycle work.
    pub item: SecKeychainItem,
}
