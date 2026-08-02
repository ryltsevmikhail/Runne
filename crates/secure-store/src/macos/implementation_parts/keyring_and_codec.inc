fn create_populated_provider_item(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
    metadata: &ProviderCredentialMetadata,
    exact_access: &ExactKeychainAccess,
    encoded: &[u8],
    failpoint: Option<CredentialPopulationFailpoint>,
) -> Result<SecKeychainItem, SecureStoreError> {
    let mut item = gocode_macos_keychain_acl::create_empty_generic_password(
        keychain,
        service,
        account,
        &metadata.encode_incomplete(),
        exact_access,
    )
    .map_err(map_acl_error)?;
    if failpoint == Some(CredentialPopulationFailpoint::EmptyItemWritten) {
        return Err(SecureStoreError::CredentialEnrollmentIncomplete);
    }
    if let Err(error) = item.set_password(encoded).map_err(map_keychain_error) {
        return if gocode_macos_keychain_acl::delete_item(&item).is_ok() {
            Err(error)
        } else {
            Err(SecureStoreError::CredentialEnrollmentIncomplete)
        };
    }
    if let Err(error) = verify_item_acl(&item, exact_access.digest()) {
        return if gocode_macos_keychain_acl::delete_item(&item).is_ok() {
            Err(error)
        } else {
            Err(SecureStoreError::CredentialEnrollmentIncomplete)
        };
    }
    if gocode_macos_keychain_acl::set_generic_password_metadata(&item, &metadata.encode()).is_err()
    {
        return Err(SecureStoreError::CredentialEnrollmentIncomplete);
    }
    if verify_item_acl(&item, exact_access.digest()).is_err() {
        return if gocode_macos_keychain_acl::delete_item(&item).is_ok() {
            Err(SecureStoreError::CredentialAccessDenied)
        } else {
            Err(SecureStoreError::CredentialEnrollmentIncomplete)
        };
    }
    Ok(item)
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
        KeychainAclError::OperationFailed => SecureStoreError::ProviderCredentialOperationFailed,
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

impl ProviderJournalKeyring for MacOsKeychainStore {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn provider_journal_key_status(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        let keychain = SecKeychain::default().map_err(|_| SecureStoreError::Unavailable)?;
        let account = self.provider_journal_key_account(key_ref);
        gocode_macos_keychain_acl::generic_password_exists(&keychain, SERVICE_NAME, &account)
            .map_err(|_| SecureStoreError::Unavailable)
            .map(|exists| {
                if exists {
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
        match security_framework::passwords::get_generic_password(SERVICE_NAME, &account) {
            Ok(encoded) => {
                let encoded = Zeroizing::new(encoded);
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
            Err(error) if error.code() == -25300 => {}
            Err(error) => {
                return Err(SecureStoreError::OperationFailed(format!(
                    "provider journal keychain read-before-set: {error}"
                )));
            }
        }
        let encoded = encode_provider_journal_key(key);
        security_framework::passwords::set_generic_password(SERVICE_NAME, &account, &encoded)
            .map_err(|error| {
                SecureStoreError::OperationFailed(format!("provider journal keychain set: {error}"))
            })
    }

    fn load_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        let account = self.provider_journal_key_account(key_ref);
        match security_framework::passwords::get_generic_password(SERVICE_NAME, &account) {
            Ok(encoded) => {
                let encoded = Zeroizing::new(encoded);
                decode_provider_journal_key(&encoded, key_ref)
            }
            Err(error) if error.code() == -25300 => {
                Err(SecureStoreError::ProviderJournalKeyNotFound)
            }
            Err(error) => Err(SecureStoreError::OperationFailed(format!(
                "provider journal keychain read: {error}"
            ))),
        }
    }

    fn delete_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
        _proof: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        let account = self.provider_journal_key_account(key_ref);
        match security_framework::passwords::delete_generic_password(SERVICE_NAME, &account) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == -25300 => {
                Err(SecureStoreError::ProviderJournalKeyNotFound)
            }
            Err(error) => Err(SecureStoreError::OperationFailed(format!(
                "provider journal keychain delete: {error}"
            ))),
        }
    }
}

impl MacOsKeychainStore {
    fn provider_journal_key_account(&self, key_ref: ProviderJournalKeyRef) -> String {
        format!(
            "{}:provider_journal:{}:{}:{}:{}",
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
