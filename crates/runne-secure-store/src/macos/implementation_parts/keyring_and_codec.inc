/// Creates one provider-credential item with its material atomically stored.
///
/// Ordering (fail-closed, macOS 27): the credential bytes and the complete
/// metadata travel in the single `SecKeychainItemCreateFromContent` call,
/// because the first `SecKeychainItemModifyAttributesAndData` of a saved item
/// erases its partition ACL record irreversibly. The saved item is then
/// verified (`finalize`: full partition and owner ACL readback) and any
/// verification failure deletes the item before the error is returned, so
/// credential material never persists without a proven partition ACL.
fn create_populated_provider_item(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
    metadata: &ProviderCredentialMetadata,
    exact_access: &ExactKeychainAccess,
    encoded: &[u8],
    failpoint: Option<CredentialPopulationFailpoint>,
) -> Result<SecKeychainItem, SecureStoreError> {
    let item = runne_macos_keychain_acl::create_populated_generic_password(
        keychain,
        service,
        account,
        &metadata.encode(),
        encoded,
        exact_access,
    )
    .map_err(map_acl_error)?;
    if failpoint == Some(CredentialPopulationFailpoint::PopulatedItemWritten) {
        // Crash boundary: the item exists with the exact creation ACL but its
        // readback proof has not happened yet, exactly as after a process exit
        // between creation and verification.
        return Err(SecureStoreError::CredentialEnrollmentIncomplete);
    }
    // `finalize` verifies the saved item's full ACL and deletes it on failure.
    item.finalize(exact_access).map_err(map_acl_error)
}

fn map_identity_access_error(_error: SecureStoreError) -> SecureStoreError {
    SecureStoreError::CredentialAccessDenied
}

const fn map_acl_error(error: KeychainAclError) -> SecureStoreError {
    match error {
        KeychainAclError::InvalidExecutable | KeychainAclError::AccessDenied => {
            SecureStoreError::CredentialAccessDenied
        }
        KeychainAclError::InvalidItemIdentity => {
            SecureStoreError::ProviderCredentialOperationFailed
        }
        KeychainAclError::OperationFailed
        | KeychainAclError::InvalidProfileBinding
        | KeychainAclError::InvalidSeal => SecureStoreError::ProviderCredentialOperationFailed,
    }
}

const fn map_keychain_error(error: security_framework::base::Error) -> SecureStoreError {
    if matches!(
        error.code(),
        ERR_SEC_AUTH_FAILED
            | ERR_SEC_INTERACTION_NOT_ALLOWED
            | ERR_SEC_NO_ACCESS_FOR_ITEM
            | ERR_SEC_INVALID_OWNER_EDIT
    ) {
        SecureStoreError::CredentialAccessDenied
    } else {
        SecureStoreError::ProviderCredentialOperationFailed
    }
}

const OPEN_JOURNAL_PREFIX: &str = "v1:";
const OPEN_JOURNAL_ACCOUNT_PREFIX: &str = "open1:";

/// Reads one journal item through the stable macOS open-ACL bridge.
///
/// macOS 27 rejects legacy SecKeychain reads of these items with
/// `errSecAuthFailed`, so the system `security` tool is the read bridge.
fn read_open_journal_item(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
    let Some(value) = runne_macos_keychain_acl::read_open_generic_password(SERVICE_NAME, account)
        .map_err(|_| SecureStoreError::Unavailable)?
    else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&value)
        .map_err(|_| SecureStoreError::CorruptProviderJournalKey)?;
    let encoded = text
        .strip_prefix(OPEN_JOURNAL_PREFIX)
        .ok_or(SecureStoreError::CorruptProviderJournalKey)?;
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map(|bytes| Some(Zeroizing::new(bytes)))
        .map_err(|_| SecureStoreError::CorruptProviderJournalKey)
}

fn write_open_journal_item(account: &str, encoded: &[u8]) -> Result<(), SecureStoreError> {
    // The system tool's password input is capped at 128 bytes, so the 88-byte
    // payload travels as compact base64 rather than hex.
    use base64::Engine as _;
    let text = format!(
        "{OPEN_JOURNAL_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(encoded)
    );
    runne_macos_keychain_acl::write_open_generic_password(SERVICE_NAME, account, &text).map_err(
        |_| SecureStoreError::OperationFailed("provider journal keychain write".into()),
    )
}

fn delete_open_journal_item(account: &str) -> Result<(), SecureStoreError> {
    runne_macos_keychain_acl::delete_open_generic_password(SERVICE_NAME, account).map_err(|_| {
        SecureStoreError::OperationFailed("provider journal keychain delete".into())
    })
}

impl ProviderJournalKeyring for MacOsKeychainStore {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn provider_journal_key_status(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        let account = self.provider_journal_key_account(key_ref);
        read_open_journal_item(&account).map(|value| {
            if value.is_some() {
                ProviderJournalKeyStatus::Available
            } else {
                ProviderJournalKeyStatus::Missing
            }
        })
    }

    fn store_provider_journal_key(
        &self,
        key: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        let account = self.provider_journal_key_account(key.key_ref());
        if let Some(encoded) = read_open_journal_item(&account)? {
            let existing = decode_provider_journal_key(&encoded, key.key_ref())?;
            return existing.with_bytes(|existing_bytes| {
                key.with_bytes(|new_bytes| {
                    if existing_bytes == new_bytes {
                        Ok(())
                    } else {
                        Err(SecureStoreError::CorruptProviderJournalKey)
                    }
                })
            });
        }
        write_open_journal_item(&account, &encode_provider_journal_key(key))
    }

    fn load_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        let account = self.provider_journal_key_account(key_ref);
        match read_open_journal_item(&account)? {
            Some(encoded) => decode_provider_journal_key(&encoded, key_ref),
            None => Err(SecureStoreError::ProviderJournalKeyNotFound),
        }
    }

    fn replace_provider_journal_key(
        &self,
        key: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        let account = self.provider_journal_key_account(key.key_ref());
        write_open_journal_item(&account, &encode_provider_journal_key(key))?;
        let stored = read_open_journal_item(&account)?
            .ok_or(SecureStoreError::ProviderJournalKeyNotFound)?;
        let stored = decode_provider_journal_key(&stored, key.key_ref())?;
        stored.with_bytes(|stored| {
            key.with_bytes(|expected| {
                if stored == expected {
                    Ok(())
                } else {
                    Err(SecureStoreError::CorruptProviderJournalKey)
                }
            })
        })
    }

    fn delete_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
        _proof: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        let account = self.provider_journal_key_account(key_ref);
        if read_open_journal_item(&account)?.is_none() {
            return Err(SecureStoreError::ProviderJournalKeyNotFound);
        }
        delete_open_journal_item(&account)
    }
}

impl MacOsKeychainStore {
    fn provider_journal_key_account(&self, key_ref: ProviderJournalKeyRef) -> String {
        // macOS 27 rejects the legacy SecKeychain path with errSecAuthFailed and
        // any `security -w` read of a legacy item blocks on a system prompt.
        // New material lives in a distinct open-ACL namespace so it is readable
        // without ever touching a legacy item.
        format!(
            "{OPEN_JOURNAL_ACCOUNT_PREFIX}{}:provider_journal:{}:{}:{}:{}",
            self.account_name,
            encode_hex(&key_ref.key_id()),
            key_ref.version(),
            encode_hex(&key_ref.runtime_authority_id()),
            key_ref.database_generation(),
        )
    }
}

fn decode_anchor(bytes: &[u8]) -> Result<u64, SecureStoreError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| SecureStoreError::CorruptAnchor)?;
    Ok(u64::from_le_bytes(bytes))
}

fn encode_security_anchor(anchor: &SecurityAnchorV1) -> Vec<u8> {
    let seal = anchor.sealed_transaction.as_bytes();
    let mut encoded = Vec::with_capacity(145 + seal.len());
    encoded.extend_from_slice(SECURITY_ANCHOR_MAGIC);
    encoded.extend_from_slice(&anchor.profile_identity_digest);
    encoded.extend_from_slice(&anchor.database_identity);
    encoded.extend_from_slice(&anchor.generation.to_be_bytes());
    encoded.extend_from_slice(&anchor.transaction_digest);
    encoded.extend_from_slice(&anchor.previous_anchor_digest);
    encoded.push(u8::try_from(seal.len()).expect("bounded seal"));
    encoded.extend_from_slice(seal);
    encoded
}

fn decode_security_anchor(bytes: &[u8]) -> Result<SecurityAnchorV1, SecureStoreError> {
    if bytes.len() < 145 || bytes.get(..8) != Some(SECURITY_ANCHOR_MAGIC) { return Err(SecureStoreError::CorruptAnchor); }
    let mut offset = 8;
    let take = |offset: &mut usize, length: usize| -> Result<&[u8], SecureStoreError> {
        let end = offset.checked_add(length).ok_or(SecureStoreError::CorruptAnchor)?;
        let value = bytes.get(*offset..end).ok_or(SecureStoreError::CorruptAnchor)?;
        *offset = end;
        Ok(value)
    };
    let profile: [u8; 32] = take(&mut offset, 32)?.try_into().map_err(|_| SecureStoreError::CorruptAnchor)?;
    let database: [u8; 32] = take(&mut offset, 32)?.try_into().map_err(|_| SecureStoreError::CorruptAnchor)?;
    let generation = u64::from_be_bytes(take(&mut offset, 8)?.try_into().map_err(|_| SecureStoreError::CorruptAnchor)?);
    let digest: [u8; 32] = take(&mut offset, 32)?.try_into().map_err(|_| SecureStoreError::CorruptAnchor)?;
    let previous: [u8; 32] = take(&mut offset, 32)?.try_into().map_err(|_| SecureStoreError::CorruptAnchor)?;
    let seal_length = usize::from(*take(&mut offset, 1)?.first().ok_or(SecureStoreError::CorruptAnchor)?);
    if offset.checked_add(seal_length) != Some(bytes.len()) { return Err(SecureStoreError::CorruptAnchor); }
    let seal = SealedTransactionTag::from_storage(take(&mut offset, seal_length)?.to_vec()).map_err(|_| SecureStoreError::CorruptAnchor)?;
    SecurityAnchorV1::new(profile, database, generation, digest, previous, seal).map_err(|_| SecureStoreError::CorruptAnchor)
}

fn encode_provider_journal_key(key: &ProviderJournalKeyMaterial) -> Zeroizing<Vec<u8>> {
    let key_ref = key.key_ref();
    let mut encoded = Zeroizing::new(Vec::with_capacity(88));
    encoded.extend_from_slice(PROVIDER_JOURNAL_KEY_MAGIC);
    encoded.extend_from_slice(&key_ref.key_id());
    encoded.extend_from_slice(&key_ref.version().to_be_bytes());
    encoded.extend_from_slice(&key_ref.runtime_authority_id());
    encoded.extend_from_slice(&key_ref.database_generation().to_be_bytes());
    key.with_bytes(|bytes| encoded.extend_from_slice(bytes));
    encoded
}

fn decode_provider_journal_key(
    encoded: &[u8],
    expected_ref: ProviderJournalKeyRef,
) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
    if encoded.len() != 88 || &encoded[..8] != PROVIDER_JOURNAL_KEY_MAGIC {
        return Err(SecureStoreError::CorruptProviderJournalKey);
    }
    let key_ref = ProviderJournalKeyRef::new(
        fixed_bytes(&encoded[8..24])?,
        u64::from_be_bytes(fixed_bytes(&encoded[24..32])?),
        fixed_bytes(&encoded[32..48])?,
        u64::from_be_bytes(fixed_bytes(&encoded[48..56])?),
    )?;
    if key_ref != expected_ref {
        return Err(SecureStoreError::CorruptProviderJournalKey);
    }
    ProviderJournalKeyMaterial::new(key_ref, fixed_bytes(&encoded[56..88])?)
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], SecureStoreError> {
    bytes
        .try_into()
        .map_err(|_| SecureStoreError::CorruptProviderJournalKey)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
