use std::fs::{File, OpenOptions};
use std::sync::Mutex;

use gocode_macos_keychain_acl::{ExactKeychainAccess, KeychainAclError};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::keychain_item::SecKeychainItem;

use crate::provider_credential::StoredProviderCredential;
use crate::{
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialMaterial,
    ProviderCredentialStatus, ProviderCredentialStore, ProviderJournalKeyDeletionProof,
    ProviderJournalKeyMaterial, ProviderJournalKeyRef, ProviderJournalKeyring, SecureStore,
    SecureStoreError,
};
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "gocode-ui";
const ACCOUNT_PREFIX: &str = "db_generation";
const PROVIDER_JOURNAL_KEY_MAGIC: &[u8; 8] = b"GCPJKV1\0";
const PROVIDER_CREDENTIAL_MIGRATION_SUFFIX: &str = ".migration-backup";
const ERR_SEC_AUTH_FAILED: i32 = -25_293;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_NO_ACCESS_FOR_ITEM: i32 = -25_243;
const ERR_SEC_INVALID_OWNER_EDIT: i32 = -25_244;
static PROVIDER_CREDENTIAL_KEYCHAIN_LOCK: Mutex<()> = Mutex::new(());
type CredentialKeychainItem = Option<(Zeroizing<Vec<u8>>, SecKeychainItem)>;

struct ProviderCredentialProcessLock {
    _file: File,
}

impl ProviderCredentialProcessLock {
    fn acquire() -> Result<Self, SecureStoreError> {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt as _;

        let path = std::env::temp_dir().join("dev.gocode.provider-credential.v1.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)?;
        file.lock()
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)?;
        Ok(Self { _file: file })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialMigrationFailpoint {
    BackupWritten,
    PrimaryDeleted,
    ReplacementWritten,
}

pub struct MacOsKeychainStore {
    account_name: String,
}

/// macOS Keychain provider-credential backend with explicit executable ACLs.
///
/// This backend is development/ad-hoc only until signed native identity
/// evidence exists; it makes no Developer ID or notarization claim.
#[derive(Debug)]
pub struct MacOsProviderCredentialStore {
    service: String,
    account: String,
}

impl MacOsProviderCredentialStore {
    /// Constructs the fixed production-shaped provider credential item.
    #[must_use]
    pub fn new() -> Self {
        Self {
            service: crate::PROVIDER_CREDENTIAL_SERVICE.to_owned(),
            account: ProviderCredentialId::OpenAi.account().to_owned(),
        }
    }

    #[cfg(test)]
    const fn with_test_item(service: String, account: String) -> Self {
        Self { service, account }
    }
}

impl Default for MacOsProviderCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOsKeychainStore {
    pub fn new(profile_id: impl AsRef<str>) -> Self {
        Self {
            account_name: format!("{ACCOUNT_PREFIX}:{}", profile_id.as_ref()),
        }
    }
}

impl SecureStore for MacOsKeychainStore {
    fn store_anchor(&self, generation: u64) -> Result<(), SecureStoreError> {
        let value = generation.to_le_bytes();
        security_framework::passwords::set_generic_password(
            SERVICE_NAME,
            &self.account_name,
            &value,
        )
        .map_err(|e| SecureStoreError::OperationFailed(format!("keychain set: {e}")))
    }

    fn read_anchor(&self) -> Result<Option<u64>, SecureStoreError> {
        match security_framework::passwords::get_generic_password(SERVICE_NAME, &self.account_name)
        {
            Ok(bytes) => decode_anchor(&bytes).map(Some),
            Err(e) => {
                // errSecItemNotFound (-25300) means no anchor exists — that's normal.
                if e.code() == -25300 {
                    return Ok(None);
                }
                Err(SecureStoreError::OperationFailed(format!(
                    "keychain read: {e}"
                )))
            }
        }
    }

    fn delete_anchor(&self) -> Result<(), SecureStoreError> {
        match security_framework::passwords::delete_generic_password(
            SERVICE_NAME,
            &self.account_name,
        ) {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.code() == -25300 {
                    // Not found is fine for delete
                    return Ok(());
                }
                Err(SecureStoreError::OperationFailed(format!(
                    "keychain delete: {e}"
                )))
            }
        }
    }
}

impl ProviderCredentialStore for MacOsProviderCredentialStore {
    fn provider_credential_status(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        self.validate_provider(provider)?;
        Self::with_noninteractive(|keychain| {
            let Some((encoded, item)) = self.find_item(keychain)? else {
                return Ok(ProviderCredentialStatus::Missing);
            };
            let stored = StoredProviderCredential::decode(&encoded)?;
            stored.validate_writer_current()?;
            verify_item_acl(&item, stored.acl_set_digest())?;
            Ok(ProviderCredentialStatus::Configured)
        })
    }

    fn store_provider_credential(
        &self,
        provider: ProviderCredentialId,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.validate_provider(provider)?;
        access
            .validate_writer_current()
            .map_err(map_identity_access_error)?;
        access.remeasure().map_err(map_identity_access_error)?;
        Self::with_noninteractive(|keychain| {
            let exact_access = ExactKeychainAccess::new(access.writer_path(), access.reader_path())
                .map_err(map_acl_error)?;
            access.remeasure().map_err(map_identity_access_error)?;
            let encoded =
                StoredProviderCredential::encode(credential, access, exact_access.digest())?;
            match self.find_item(keychain)? {
                Some((existing, mut item)) => {
                    let stored = StoredProviderCredential::decode(&existing)?;
                    stored.validate_writer_current()?;
                    if !stored.access_matches(access) {
                        return Err(SecureStoreError::CredentialAclMigrationRequired);
                    }
                    verify_item_acl(&item, stored.acl_set_digest())?;
                    item.set_password(&encoded).map_err(map_keychain_error)?;
                    verify_item_acl(&item, exact_access.digest())
                }
                None => create_populated_provider_item(
                    keychain,
                    &self.service,
                    &self.account,
                    &exact_access,
                    &encoded,
                )
                .map(|_| ()),
            }
        })
    }

    fn load_provider_credential(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.validate_provider(provider)?;
        Self::with_noninteractive(|keychain| {
            let Some((encoded, item)) = self.find_item(keychain)? else {
                return Err(SecureStoreError::ProviderCredentialNotFound);
            };
            let stored = StoredProviderCredential::decode(&encoded)?;
            stored.validate_reader_current()?;
            verify_item_acl(&item, stored.acl_set_digest())?;
            Ok(stored.into_material())
        })
    }

    fn delete_provider_credential(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        self.validate_provider(provider)?;
        Self::with_noninteractive(|keychain| {
            let Some((encoded, item)) = self.find_item(keychain)? else {
                return Ok(());
            };
            let stored = StoredProviderCredential::decode(&encoded)?;
            stored.validate_writer_current()?;
            verify_item_acl(&item, stored.acl_set_digest())?;
            gocode_macos_keychain_acl::delete_item(&item).map_err(map_acl_error)
        })
    }

    fn migrate_provider_credential_access(
        &self,
        provider: ProviderCredentialId,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.migrate_provider_credential_access_inner(provider, current, replacement, None)
    }
}

impl MacOsProviderCredentialStore {
    fn migrate_provider_credential_access_inner(
        &self,
        provider: ProviderCredentialId,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
        failpoint: Option<CredentialMigrationFailpoint>,
    ) -> Result<(), SecureStoreError> {
        self.validate_provider(provider)?;
        current
            .validate_writer_current()
            .map_err(map_identity_access_error)?;
        if current.writer_identity() != replacement.writer_identity() {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        current.remeasure().map_err(map_identity_access_error)?;
        replacement.remeasure().map_err(map_identity_access_error)?;
        Self::with_noninteractive(|keychain| {
            self.reconcile_migration_backup(keychain, current, replacement)?;
            let Some((encoded, item)) = self.find_primary_item(keychain)? else {
                return Err(SecureStoreError::ProviderCredentialNotFound);
            };
            let stored = StoredProviderCredential::decode(&encoded)?;
            if !stored.access_matches(current) && !stored.access_matches(replacement) {
                return Err(SecureStoreError::CredentialAclMigrationRequired);
            }
            verify_item_acl(&item, stored.acl_set_digest())?;
            let replacement_access =
                ExactKeychainAccess::new(replacement.writer_path(), replacement.reader_path())
                    .map_err(map_acl_error)?;
            replacement.remeasure().map_err(map_identity_access_error)?;
            if stored.access_matches(replacement) {
                return verify_item_acl(&item, replacement_access.digest())
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete);
            }
            let current_access =
                ExactKeychainAccess::new(current.writer_path(), current.reader_path())
                    .map_err(map_acl_error)?;
            if stored.acl_set_digest() != current_access.digest() {
                return Err(SecureStoreError::CredentialAccessDenied);
            }
            let material = stored.into_material();
            let replacement_encoded = StoredProviderCredential::encode(
                &material,
                replacement,
                replacement_access.digest(),
            )?;
            let migration_service = self.migration_service();
            let backup_item = create_populated_provider_item(
                keychain,
                &migration_service,
                &self.account,
                &current_access,
                &encoded,
            )?;
            verify_item_acl(&backup_item, current_access.digest())?;
            if failpoint == Some(CredentialMigrationFailpoint::BackupWritten) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            gocode_macos_keychain_acl::delete_item(&item)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
            if failpoint == Some(CredentialMigrationFailpoint::PrimaryDeleted) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let Ok(replacement_item) = create_populated_provider_item(
                keychain,
                &self.service,
                &self.account,
                &replacement_access,
                &replacement_encoded,
            ) else {
                gocode_macos_keychain_acl::rename_item_service(&backup_item, &self.service)
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            };
            if verify_item_acl(&replacement_item, replacement_access.digest()).is_err() {
                if gocode_macos_keychain_acl::delete_item(&replacement_item).is_ok() {
                    let _ =
                        gocode_macos_keychain_acl::rename_item_service(&backup_item, &self.service);
                }
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            if failpoint == Some(CredentialMigrationFailpoint::ReplacementWritten) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            gocode_macos_keychain_acl::delete_item(&backup_item)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
            Ok(())
        })
    }

    fn reconcile_migration_backup(
        &self,
        keychain: &SecKeychain,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let Some((backup_encoded, backup_item)) = self.find_migration_backup(keychain)? else {
            return Ok(());
        };
        let backup = StoredProviderCredential::decode(&backup_encoded)?;
        if !backup.access_matches(current) {
            return Err(SecureStoreError::CredentialMigrationIncomplete);
        }
        let current_access = ExactKeychainAccess::new(current.writer_path(), current.reader_path())
            .map_err(map_acl_error)?;
        if backup.acl_set_digest() != current_access.digest() {
            return Err(SecureStoreError::CredentialMigrationIncomplete);
        }
        verify_item_acl(&backup_item, current_access.digest())?;
        match self.find_primary_item(keychain) {
            Ok(None) => {
                gocode_macos_keychain_acl::rename_item_service(&backup_item, &self.service)
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                Err(SecureStoreError::CredentialMigrationIncomplete)
            }
            Ok(Some((primary_encoded, primary_item))) => {
                let primary = StoredProviderCredential::decode(&primary_encoded)?;
                if primary.access_matches(current) {
                    if primary_encoded.as_slice() != backup_encoded.as_slice() {
                        return Err(SecureStoreError::CredentialMigrationIncomplete);
                    }
                    verify_item_acl(&primary_item, current_access.digest())?;
                    gocode_macos_keychain_acl::delete_item(&backup_item)
                        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)
                } else if primary.access_matches(replacement) {
                    let replacement_access = ExactKeychainAccess::new(
                        replacement.writer_path(),
                        replacement.reader_path(),
                    )
                    .map_err(map_acl_error)?;
                    if primary.acl_set_digest() != replacement_access.digest() {
                        return Err(SecureStoreError::CredentialMigrationIncomplete);
                    }
                    verify_item_acl(&primary_item, replacement_access.digest())?;
                    gocode_macos_keychain_acl::delete_item(&backup_item)
                        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)
                } else {
                    Err(SecureStoreError::CredentialMigrationIncomplete)
                }
            }
            Err(SecureStoreError::CredentialAccessDenied) => {
                Err(SecureStoreError::CredentialMigrationIncomplete)
            }
            Err(error) => Err(error),
        }
    }
    fn validate_provider(&self, provider: ProviderCredentialId) -> Result<(), SecureStoreError> {
        if provider.account() != self.account
            && self.account == ProviderCredentialId::OpenAi.account()
        {
            return Err(SecureStoreError::ProviderCredentialOperationFailed);
        }
        Ok(())
    }

    fn with_noninteractive<T>(
        operation: impl FnOnce(&SecKeychain) -> Result<T, SecureStoreError>,
    ) -> Result<T, SecureStoreError> {
        let _operation_lock = PROVIDER_CREDENTIAL_KEYCHAIN_LOCK
            .lock()
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)?;
        let _process_lock = ProviderCredentialProcessLock::acquire()?;
        let _interaction_lock =
            SecKeychain::disable_user_interaction().map_err(map_keychain_error)?;
        let keychain = SecKeychain::default().map_err(map_keychain_error)?;
        operation(&keychain)
    }

    fn find_item(
        &self,
        keychain: &SecKeychain,
    ) -> Result<CredentialKeychainItem, SecureStoreError> {
        if let Some(primary) = self.find_named_item(keychain, &self.service)? {
            return Ok(Some(primary));
        }
        let Some((encoded, item)) = self.find_named_item(keychain, &self.migration_service())?
        else {
            return Ok(None);
        };
        let stored = StoredProviderCredential::decode(&encoded)?;
        if stored.validate_writer_current().is_err() && stored.validate_reader_current().is_err() {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        verify_item_acl(&item, stored.acl_set_digest())?;
        gocode_macos_keychain_acl::rename_item_service(&item, &self.service)
            .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
        Ok(Some((encoded, item)))
    }

    fn find_primary_item(
        &self,
        keychain: &SecKeychain,
    ) -> Result<CredentialKeychainItem, SecureStoreError> {
        self.find_named_item(keychain, &self.service)
    }

    fn find_migration_backup(
        &self,
        keychain: &SecKeychain,
    ) -> Result<CredentialKeychainItem, SecureStoreError> {
        self.find_named_item(keychain, &self.migration_service())
    }

    fn find_named_item(
        &self,
        keychain: &SecKeychain,
        service: &str,
    ) -> Result<CredentialKeychainItem, SecureStoreError> {
        match keychain.find_generic_password(service, &self.account) {
            Ok((password, item)) => Ok(Some((Zeroizing::new(password.to_vec()), item))),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(map_keychain_error(error)),
        }
    }

    fn migration_service(&self) -> String {
        format!("{}{PROVIDER_CREDENTIAL_MIGRATION_SUFFIX}", self.service)
    }
}

fn verify_item_acl(
    item: &SecKeychainItem,
    expected_digest: [u8; 32],
) -> Result<(), SecureStoreError> {
    gocode_macos_keychain_acl::verify_item_access(item, expected_digest).map_err(map_acl_error)
}

fn create_populated_provider_item(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
    exact_access: &ExactKeychainAccess,
    encoded: &[u8],
) -> Result<SecKeychainItem, SecureStoreError> {
    let mut item = gocode_macos_keychain_acl::create_empty_generic_password(
        keychain,
        service,
        account,
        exact_access,
    )
    .map_err(map_acl_error)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    struct ProviderCredentialCleanup {
        service: String,
        account: String,
    }

    impl Drop for ProviderCredentialCleanup {
        fn drop(&mut self) {
            let _ = security_framework::passwords::delete_generic_password(
                &self.service,
                &self.account,
            );
            let _ = security_framework::passwords::delete_generic_password(
                &format!("{}{PROVIDER_CREDENTIAL_MIGRATION_SUFFIX}", self.service),
                &self.account,
            );
        }
    }

    struct ExecutableCopy(PathBuf);

    impl ExecutableCopy {
        fn new(source: &Path, label: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "gocode-keychain-acl-{label}-{}-{unique}",
                std::process::id()
            ));
            std::fs::copy(source, &path).expect("copy executable");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))
                .expect("restrict executable copy");
            Self(path)
        }

        fn replace_with(&self, source: &Path) {
            std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700))
                .expect("make executable copy replaceable");
            std::fs::copy(source, &self.0).expect("replace executable copy");
            std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o500))
                .expect("restrict replaced executable copy");
        }
    }

    impl Drop for ExecutableCopy {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn unique_provider_store(
        label: &str,
    ) -> (MacOsProviderCredentialStore, ProviderCredentialCleanup) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let service = format!(
            "{}.test.{label}.{}.{}",
            crate::PROVIDER_CREDENTIAL_SERVICE,
            std::process::id(),
            unique
        );
        let account = format!("openai-test-{unique}");
        let cleanup = ProviderCredentialCleanup {
            service: service.clone(),
            account: account.clone(),
        };
        (
            MacOsProviderCredentialStore::with_test_item(service, account),
            cleanup,
        )
    }

    #[test]
    fn profiles_use_distinct_keychain_accounts() {
        let first = MacOsKeychainStore::new("profile-a");
        let second = MacOsKeychainStore::new("profile-b");

        assert_ne!(first.account_name, second.account_name);
    }

    #[test]
    fn rejects_malformed_anchor_bytes() {
        let error = decode_anchor(&[1, 2, 3]).expect_err("malformed anchor");

        assert!(matches!(error, SecureStoreError::CorruptAnchor));
    }

    #[test]
    fn provider_journal_key_codec_rejects_changed_binding_and_corruption() {
        let key_ref = ProviderJournalKeyRef::new([1; 16], 2, [3; 16], 4).unwrap();
        let key = ProviderJournalKeyMaterial::new(key_ref, [5; 32]).unwrap();
        let encoded = encode_provider_journal_key(&key);

        assert_eq!(
            decode_provider_journal_key(
                &encoded,
                ProviderJournalKeyRef::new([1; 16], 2, [3; 16], 5).unwrap(),
            )
            .unwrap_err(),
            SecureStoreError::CorruptProviderJournalKey
        );
        let mut corrupt = encoded;
        corrupt[0] ^= 1;
        assert_eq!(
            decode_provider_journal_key(&corrupt, key_ref).unwrap_err(),
            SecureStoreError::CorruptProviderJournalKey
        );
    }

    #[test]
    fn store_read_delete_roundtrip() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let profile = format!("test-{}-{unique}", std::process::id());
        let store = MacOsKeychainStore::new(&profile);
        // Clean up any leftover from previous runs
        let _ = store.delete_anchor();

        assert_eq!(store.read_anchor().unwrap(), None);

        store.store_anchor(42).unwrap();
        assert_eq!(store.read_anchor().unwrap(), Some(42));

        store.store_anchor(99).unwrap();
        assert_eq!(store.read_anchor().unwrap(), Some(99));

        store.delete_anchor().unwrap();
        assert_eq!(store.read_anchor().unwrap(), None);
    }

    #[test]
    fn provider_journal_key_roundtrip_rejects_conflicting_overwrite() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let profile = format!("provider-journal-test-{}-{unique}", std::process::id());
        let store = MacOsKeychainStore::new(&profile);
        let key_ref = ProviderJournalKeyRef::new([11; 16], 1, [12; 16], 13).unwrap();
        let key = ProviderJournalKeyMaterial::new(key_ref, [14; 32]).unwrap();

        store.store_provider_journal_key(&key).unwrap();
        let loaded = store.load_provider_journal_key(key_ref).unwrap();
        assert_eq!(loaded.with_bytes(|bytes| *bytes), [14; 32]);
        let conflict = ProviderJournalKeyMaterial::new(key_ref, [15; 32]).unwrap();
        assert_eq!(
            store.store_provider_journal_key(&conflict),
            Err(SecureStoreError::CorruptProviderJournalKey)
        );
        assert_eq!(
            store
                .load_provider_journal_key(key_ref)
                .unwrap()
                .with_bytes(|bytes| *bytes),
            [14; 32]
        );

        store
            .delete_provider_journal_key(
                key_ref,
                ProviderJournalKeyDeletionProof::for_verified_catalog(0, 0, [16; 32]).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store.load_provider_journal_key(key_ref).unwrap_err(),
            SecureStoreError::ProviderJournalKeyNotFound
        );
    }

    #[test]
    fn provider_journal_rotation_retains_versions_and_database_binding() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let profile = format!("provider-journal-rotation-{}-{unique}", std::process::id());
        let store = MacOsKeychainStore::new(&profile);
        let first_ref = ProviderJournalKeyRef::new([21; 16], 1, [22; 16], 23).unwrap();
        let second_ref = ProviderJournalKeyRef::new([21; 16], 2, [22; 16], 23).unwrap();
        let wrong_generation = ProviderJournalKeyRef::new([21; 16], 1, [22; 16], 24).unwrap();
        let first = ProviderJournalKeyMaterial::new(first_ref, [24; 32]).unwrap();
        let second = ProviderJournalKeyMaterial::new(second_ref, [25; 32]).unwrap();

        store.store_provider_journal_key(&first).unwrap();
        store.store_provider_journal_key(&second).unwrap();
        assert_eq!(
            store
                .load_provider_journal_key(first_ref)
                .unwrap()
                .with_bytes(|bytes| *bytes),
            [24; 32]
        );
        assert_eq!(
            store
                .load_provider_journal_key(second_ref)
                .unwrap()
                .with_bytes(|bytes| *bytes),
            [25; 32]
        );
        assert_eq!(
            store
                .load_provider_journal_key(wrong_generation)
                .unwrap_err(),
            SecureStoreError::ProviderJournalKeyNotFound
        );

        let proof = ProviderJournalKeyDeletionProof::for_verified_catalog(0, 0, [26; 32]).unwrap();
        store.delete_provider_journal_key(first_ref, proof).unwrap();
        store
            .delete_provider_journal_key(second_ref, proof)
            .unwrap();
    }

    #[test]
    fn provider_credential_keychain_roundtrip_has_exact_acl_and_idempotent_cleanup() {
        let (store, _cleanup) = unique_provider_store("roundtrip");
        let current = std::env::current_exe().expect("current test executable");
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let first = ProviderCredentialMaterial::new(b"native-test-first".to_vec()).unwrap();
        let replacement =
            ProviderCredentialMaterial::new(b"native-test-replacement".to_vec()).unwrap();

        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi)
                .unwrap(),
            ProviderCredentialStatus::Missing
        );
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &first, &policy)
            .unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap()
                .with_bytes(<[u8]>::to_vec),
            b"native-test-first"
        );
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &replacement, &policy)
            .unwrap();
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap()
                .with_bytes(<[u8]>::to_vec),
            b"native-test-replacement"
        );
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi)
                .unwrap(),
            ProviderCredentialStatus::Missing
        );
    }

    #[test]
    fn provider_credential_rejects_writer_read_and_replaced_reader_without_prompt() {
        let (store, _cleanup) = unique_provider_store("negative-reader");
        let current = std::env::current_exe().expect("current test executable");
        let policy = ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        let credential = ProviderCredentialMaterial::new(b"native-test-negative".to_vec()).unwrap();
        let _exact = ExactKeychainAccess::new(&current, Path::new("/bin/echo")).unwrap();

        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &policy)
            .unwrap();
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap_err(),
            SecureStoreError::CredentialAccessDenied
        );
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();

        let reader = ExecutableCopy::new(&current, "reader-replacement");
        let stale_policy = ProviderCredentialAccessPolicy::new(&current, &reader.0).unwrap();
        reader.replace_with(Path::new("/bin/echo"));
        assert_eq!(
            store.store_provider_credential(
                ProviderCredentialId::OpenAi,
                &credential,
                &stale_policy,
            ),
            Err(SecureStoreError::CredentialAccessDenied)
        );
    }

    #[test]
    fn provider_credential_acl_migration_is_explicit_and_preserves_material() {
        let (store, _cleanup) = unique_provider_store("migration");
        let current = std::env::current_exe().expect("current test executable");
        let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-migration".to_vec()).unwrap();

        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &current_policy)
            .unwrap();
        store
            .migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            )
            .unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap_err(),
            SecureStoreError::CredentialAccessDenied
        );
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();
    }

    #[test]
    fn provider_credential_migration_recovers_verified_backup_after_restart_boundaries() {
        for failpoint in [
            CredentialMigrationFailpoint::BackupWritten,
            CredentialMigrationFailpoint::PrimaryDeleted,
            CredentialMigrationFailpoint::ReplacementWritten,
        ] {
            let (store, _cleanup) = unique_provider_store(match failpoint {
                CredentialMigrationFailpoint::BackupWritten => "recover-after-backup",
                CredentialMigrationFailpoint::PrimaryDeleted => "recover-after-delete",
                CredentialMigrationFailpoint::ReplacementWritten => "recover-after-replacement",
            });
            let current = std::env::current_exe().expect("current test executable");
            let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
            let replacement_policy =
                ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
            let credential =
                ProviderCredentialMaterial::new(b"native-test-crash-recovery".to_vec()).unwrap();

            store
                .store_provider_credential(
                    ProviderCredentialId::OpenAi,
                    &credential,
                    &current_policy,
                )
                .unwrap();
            assert_eq!(
                store.migrate_provider_credential_access_inner(
                    ProviderCredentialId::OpenAi,
                    &current_policy,
                    &replacement_policy,
                    Some(failpoint),
                ),
                Err(SecureStoreError::CredentialMigrationIncomplete)
            );

            if failpoint == CredentialMigrationFailpoint::PrimaryDeleted {
                assert_eq!(
                    store
                        .provider_credential_status(ProviderCredentialId::OpenAi)
                        .unwrap(),
                    ProviderCredentialStatus::Configured
                );
                assert_eq!(
                    store
                        .load_provider_credential(ProviderCredentialId::OpenAi)
                        .unwrap()
                        .with_bytes(<[u8]>::to_vec),
                    b"native-test-crash-recovery"
                );
            }

            store
                .migrate_provider_credential_access(
                    ProviderCredentialId::OpenAi,
                    &current_policy,
                    &replacement_policy,
                )
                .unwrap();
            assert_eq!(
                store
                    .provider_credential_status(ProviderCredentialId::OpenAi)
                    .unwrap(),
                ProviderCredentialStatus::Configured
            );
            store
                .delete_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap();
        }
    }

    #[test]
    fn provider_credential_migration_rejects_writer_identity_change() {
        let current = std::env::current_exe().expect("current test executable");
        let replacement_writer = ExecutableCopy::new(&current, "replacement-writer");
        let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&replacement_writer.0, &current).unwrap();
        let (store, _cleanup) = unique_provider_store("writer-migration-denied");

        assert_eq!(
            store.migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            ),
            Err(SecureStoreError::CredentialAccessDenied)
        );
    }

    #[test]
    fn provider_credential_process_lock_is_cross_process() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let marker = std::env::temp_dir().join(format!(
            "gocode-provider-lock-marker-{}-{unique}",
            std::process::id()
        ));
        let process_lock = ProviderCredentialProcessLock::acquire().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "macos::tests::provider_credential_process_lock_child",
                "--nocapture",
            ])
            .env("GOCODE_PROVIDER_LOCK_TEST_MARKER", &marker)
            .spawn()
            .expect("spawn lock contender");

        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(child.try_wait().unwrap().is_none());
        assert!(!marker.exists());
        drop(process_lock);
        assert!(child.wait().unwrap().success());
        assert_eq!(std::fs::read(&marker).unwrap(), b"acquired");
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn provider_credential_process_lock_child() {
        let Some(marker) = std::env::var_os("GOCODE_PROVIDER_LOCK_TEST_MARKER") else {
            return;
        };
        let _process_lock = ProviderCredentialProcessLock::acquire().unwrap();
        std::fs::write(marker, b"acquired").unwrap();
    }
}
