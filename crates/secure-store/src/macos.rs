use std::sync::Mutex;

#[cfg(test)]
use std::cell::Cell;

use gocode_macos_keychain_acl::{
    ExactKeychainAccess, KeychainAclError, ProviderCredentialProcessLock,
};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::keychain_item::SecKeychainItem;

use crate::provider_credential::{ProviderCredentialMetadata, StoredProviderCredential};
use crate::{
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialMaterial,
    ProviderCredentialStatus, ProviderCredentialStore, ProviderJournalKeyDeletionProof,
    ProviderJournalKeyMaterial, ProviderJournalKeyRef, ProviderJournalKeyStatus,
    ProviderJournalKeyring, SecureStore, SecureStoreError,
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
#[cfg(test)]
std::thread_local! {
    static PROVIDER_CREDENTIAL_PASSWORD_READS: Cell<usize> = const { Cell::new(0) };
}
type CredentialKeychainItem = Option<(Zeroizing<Vec<u8>>, SecKeychainItem)>;
type CredentialMetadataItem = Option<(ProviderCredentialMetadata, SecKeychainItem)>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialMigrationFailpoint {
    BackupEmptyWritten,
    BackupWritten,
    PrimaryDeleted,
    ReplacementEmptyWritten,
    ReplacementWritten,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialPopulationFailpoint {
    EmptyItemWritten,
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
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        self.validate_provider(provider)?;
        expected_access
            .validate_writer_or_reader_current()
            .map_err(map_identity_access_error)?;
        expected_access
            .remeasure()
            .map_err(map_identity_access_error)?;
        let exact_access =
            ExactKeychainAccess::new(expected_access.writer_path(), expected_access.reader_path())
                .map_err(map_acl_error)?;
        expected_access
            .remeasure()
            .map_err(map_identity_access_error)?;
        Self::with_noninteractive(|keychain| match self.find_metadata_pair(keychain)? {
            (None, None) => Ok(ProviderCredentialStatus::Missing),
            (Some((metadata, item)), None) => {
                if !metadata.access_matches(expected_access)
                    || metadata.acl_set_digest() != exact_access.digest()
                {
                    return Err(SecureStoreError::CredentialAccessDenied);
                }
                verify_item_acl(&item, exact_access.digest())?;
                if !metadata.is_complete() {
                    return Err(SecureStoreError::CredentialEnrollmentIncomplete);
                }
                Ok(ProviderCredentialStatus::Configured)
            }
            _ => Err(SecureStoreError::CredentialMigrationIncomplete),
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
            let metadata = ProviderCredentialMetadata::from_access(access, exact_access.digest());
            let encoded =
                StoredProviderCredential::encode(credential, access, exact_access.digest())?;
            match self.find_metadata_pair(keychain)? {
                (Some((existing_metadata, metadata_item)), None) => {
                    existing_metadata.validate_writer_current()?;
                    if !existing_metadata.access_matches(access) {
                        return Err(SecureStoreError::CredentialAclMigrationRequired);
                    }
                    if existing_metadata.acl_set_digest() != exact_access.digest() {
                        return Err(SecureStoreError::CredentialAccessDenied);
                    }
                    verify_item_acl(&metadata_item, exact_access.digest())?;
                    if !existing_metadata.is_complete() {
                        gocode_macos_keychain_acl::delete_item(&metadata_item)
                            .map_err(map_acl_error)?;
                        return create_populated_provider_item(
                            keychain,
                            &self.service,
                            &self.account,
                            &metadata,
                            &exact_access,
                            &encoded,
                            None,
                        )
                        .map(|_| ());
                    }
                    let Some((existing, mut item)) = self.find_primary_item(keychain)? else {
                        return Err(SecureStoreError::CredentialEnrollmentIncomplete);
                    };
                    let stored = StoredProviderCredential::decode(&existing)?;
                    if !stored.metadata_matches(&existing_metadata) {
                        return Err(SecureStoreError::CorruptProviderCredential);
                    }
                    if !stored.access_matches(access) {
                        return Err(SecureStoreError::CredentialAclMigrationRequired);
                    }
                    verify_item_acl(&item, exact_access.digest())?;
                    item.set_password(&encoded).map_err(map_keychain_error)?;
                    verify_item_acl(&item, exact_access.digest())
                }
                (None, None) => create_populated_provider_item(
                    keychain,
                    &self.service,
                    &self.account,
                    &metadata,
                    &exact_access,
                    &encoded,
                    None,
                )
                .map(|_| ()),
                _ => Err(SecureStoreError::CredentialMigrationIncomplete),
            }
        })
    }

    fn load_provider_credential(
        &self,
        provider: ProviderCredentialId,
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.validate_provider(provider)?;
        expected_access
            .validate_reader_current()
            .map_err(map_identity_access_error)?;
        expected_access
            .remeasure()
            .map_err(map_identity_access_error)?;
        let exact_access =
            ExactKeychainAccess::new(expected_access.writer_path(), expected_access.reader_path())
                .map_err(map_acl_error)?;
        expected_access
            .remeasure()
            .map_err(map_identity_access_error)?;
        Self::with_noninteractive(|keychain| {
            let (metadata, metadata_item) = match self.find_metadata_pair(keychain)? {
                (Some(primary), None) => primary,
                (None, None) => return Err(SecureStoreError::ProviderCredentialNotFound),
                _ => return Err(SecureStoreError::CredentialMigrationIncomplete),
            };
            if !metadata.access_matches(expected_access)
                || metadata.acl_set_digest() != exact_access.digest()
            {
                return Err(SecureStoreError::CredentialAccessDenied);
            }
            verify_item_acl(&metadata_item, exact_access.digest())?;
            if !metadata.is_complete() {
                return Err(SecureStoreError::CredentialEnrollmentIncomplete);
            }
            let Some((encoded, item)) = self.find_primary_item(keychain)? else {
                return Err(SecureStoreError::CredentialEnrollmentIncomplete);
            };
            let stored = StoredProviderCredential::decode(&encoded)?;
            if !stored.metadata_matches(&metadata) {
                return Err(SecureStoreError::CorruptProviderCredential);
            }
            if !stored.access_matches(expected_access)
                || stored.acl_set_digest() != exact_access.digest()
            {
                return Err(SecureStoreError::CredentialAccessDenied);
            }
            verify_item_acl(&item, exact_access.digest())?;
            Ok(stored.into_material())
        })
    }

    fn delete_provider_credential(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        self.validate_provider(provider)?;
        Self::with_noninteractive(|keychain| {
            let (primary, backup) = self.find_metadata_pair(keychain)?;
            for (metadata, item) in [backup, primary].into_iter().flatten() {
                metadata.validate_writer_current()?;
                verify_item_acl(&item, metadata.acl_set_digest())?;
                gocode_macos_keychain_acl::delete_item(&item).map_err(map_acl_error)?;
            }
            Ok(())
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
    // Keep crash boundaries in one linear sequence so mutation order remains auditable.
    #[allow(clippy::too_many_lines)]
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
            let Some((metadata, metadata_item)) =
                self.find_named_metadata(keychain, &self.service)?
            else {
                return Err(SecureStoreError::ProviderCredentialNotFound);
            };
            let current_access =
                ExactKeychainAccess::new(current.writer_path(), current.reader_path())
                    .map_err(map_acl_error)?;
            let replacement_access =
                ExactKeychainAccess::new(replacement.writer_path(), replacement.reader_path())
                    .map_err(map_acl_error)?;
            replacement.remeasure().map_err(map_identity_access_error)?;
            let expected_digest = if metadata.access_matches(current) {
                current_access.digest()
            } else if metadata.access_matches(replacement) {
                replacement_access.digest()
            } else {
                return Err(SecureStoreError::CredentialAclMigrationRequired);
            };
            if metadata.acl_set_digest() != expected_digest {
                return Err(SecureStoreError::CredentialAccessDenied);
            }
            verify_item_acl(&metadata_item, expected_digest)?;
            if !metadata.is_complete() {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let Some((encoded, item)) = self.find_primary_item(keychain)? else {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            };
            let stored = StoredProviderCredential::decode(&encoded)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
            if !stored.metadata_matches(&metadata) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            if !stored.access_matches(current) && !stored.access_matches(replacement) {
                return Err(SecureStoreError::CredentialAclMigrationRequired);
            }
            if stored.acl_set_digest() != expected_digest {
                return Err(SecureStoreError::CredentialAccessDenied);
            }
            verify_item_acl(&item, expected_digest)?;
            if stored.access_matches(replacement) {
                return verify_item_acl(&item, replacement_access.digest())
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete);
            }
            let material = stored.into_material();
            let current_metadata =
                ProviderCredentialMetadata::from_access(current, current_access.digest());
            let replacement_metadata =
                ProviderCredentialMetadata::from_access(replacement, replacement_access.digest());
            let replacement_encoded = StoredProviderCredential::encode(
                &material,
                replacement,
                replacement_access.digest(),
            )?;
            let migration_service = self.migration_service();
            let backup_result = create_populated_provider_item(
                keychain,
                &migration_service,
                &self.account,
                &current_metadata,
                &current_access,
                &encoded,
                (failpoint == Some(CredentialMigrationFailpoint::BackupEmptyWritten))
                    .then_some(CredentialPopulationFailpoint::EmptyItemWritten),
            );
            if failpoint == Some(CredentialMigrationFailpoint::BackupEmptyWritten) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let backup_item = backup_result?;
            verify_item_acl(&backup_item, current_access.digest())?;
            if failpoint == Some(CredentialMigrationFailpoint::BackupWritten) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            gocode_macos_keychain_acl::delete_item(&item)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
            if failpoint == Some(CredentialMigrationFailpoint::PrimaryDeleted) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let replacement_result = create_populated_provider_item(
                keychain,
                &self.service,
                &self.account,
                &replacement_metadata,
                &replacement_access,
                &replacement_encoded,
                (failpoint == Some(CredentialMigrationFailpoint::ReplacementEmptyWritten))
                    .then_some(CredentialPopulationFailpoint::EmptyItemWritten),
            );
            if failpoint == Some(CredentialMigrationFailpoint::ReplacementEmptyWritten) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let Ok(replacement_item) = replacement_result else {
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

    // Keep complete-copy selection and destructive steps visibly ordered.
    #[allow(clippy::too_many_lines)]
    fn reconcile_migration_backup(
        &self,
        keychain: &SecKeychain,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let Some((backup_metadata, backup_item)) =
            self.find_named_metadata(keychain, &self.migration_service())?
        else {
            return Ok(());
        };
        let current_access = ExactKeychainAccess::new(current.writer_path(), current.reader_path())
            .map_err(map_acl_error)?;
        let replacement_access =
            ExactKeychainAccess::new(replacement.writer_path(), replacement.reader_path())
                .map_err(map_acl_error)?;
        verify_migration_metadata(&backup_metadata, &backup_item, current, &current_access)?;

        let primary_metadata = self.find_named_metadata(keychain, &self.service)?;
        if !backup_metadata.is_complete() {
            let Some((primary_metadata, primary_item)) = primary_metadata else {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            };
            if !primary_metadata.is_complete() {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            if primary_metadata.access_matches(current) {
                verify_migration_metadata(
                    &primary_metadata,
                    &primary_item,
                    current,
                    &current_access,
                )?;
            } else if primary_metadata.access_matches(replacement) {
                verify_migration_metadata(
                    &primary_metadata,
                    &primary_item,
                    replacement,
                    &replacement_access,
                )?;
            } else {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let Some((primary_encoded, _)) = self.find_primary_item(keychain)? else {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            };
            let primary = StoredProviderCredential::decode(&primary_encoded)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
            if !primary.metadata_matches(&primary_metadata) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            return gocode_macos_keychain_acl::delete_item(&backup_item)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete);
        }

        let Some((backup_encoded, _)) = self.find_migration_backup(keychain)? else {
            return Err(SecureStoreError::CredentialMigrationIncomplete);
        };
        let backup = StoredProviderCredential::decode(&backup_encoded)
            .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
        if !backup.metadata_matches(&backup_metadata) || !backup.access_matches(current) {
            return Err(SecureStoreError::CredentialMigrationIncomplete);
        }

        match primary_metadata {
            None => {
                gocode_macos_keychain_acl::rename_item_service(&backup_item, &self.service)
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                Err(SecureStoreError::CredentialMigrationIncomplete)
            }
            Some((primary_metadata, primary_item)) => {
                if !primary_metadata.is_complete() {
                    if primary_metadata.access_matches(current) {
                        verify_migration_metadata(
                            &primary_metadata,
                            &primary_item,
                            current,
                            &current_access,
                        )?;
                    } else if primary_metadata.access_matches(replacement) {
                        verify_migration_metadata(
                            &primary_metadata,
                            &primary_item,
                            replacement,
                            &replacement_access,
                        )?;
                    } else {
                        return Err(SecureStoreError::CredentialMigrationIncomplete);
                    }
                    gocode_macos_keychain_acl::delete_item(&primary_item)
                        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                    gocode_macos_keychain_acl::rename_item_service(&backup_item, &self.service)
                        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                    return Err(SecureStoreError::CredentialMigrationIncomplete);
                }
                if primary_metadata.access_matches(current) {
                    verify_migration_metadata(
                        &primary_metadata,
                        &primary_item,
                        current,
                        &current_access,
                    )?;
                } else if primary_metadata.access_matches(replacement) {
                    verify_migration_metadata(
                        &primary_metadata,
                        &primary_item,
                        replacement,
                        &replacement_access,
                    )?;
                } else {
                    return Err(SecureStoreError::CredentialMigrationIncomplete);
                }
                let Some((primary_encoded, _)) = self.find_primary_item(keychain)? else {
                    return Err(SecureStoreError::CredentialMigrationIncomplete);
                };
                let primary = StoredProviderCredential::decode(&primary_encoded)
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                if !primary.metadata_matches(&primary_metadata) {
                    return Err(SecureStoreError::CredentialMigrationIncomplete);
                }
                if primary.access_matches(current) {
                    if primary_encoded.as_slice() != backup_encoded.as_slice() {
                        return Err(SecureStoreError::CredentialMigrationIncomplete);
                    }
                    gocode_macos_keychain_acl::delete_item(&backup_item)
                        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)
                } else if primary.access_matches(replacement) {
                    if primary.acl_set_digest() != replacement_access.digest() {
                        return Err(SecureStoreError::CredentialMigrationIncomplete);
                    }
                    gocode_macos_keychain_acl::delete_item(&backup_item)
                        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)
                } else {
                    Err(SecureStoreError::CredentialMigrationIncomplete)
                }
            }
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
        let _process_lock = ProviderCredentialProcessLock::acquire().map_err(map_acl_error)?;
        let _interaction_lock =
            SecKeychain::disable_user_interaction().map_err(map_keychain_error)?;
        let keychain = SecKeychain::default().map_err(map_keychain_error)?;
        operation(&keychain)
    }

    fn find_metadata_pair(
        &self,
        keychain: &SecKeychain,
    ) -> Result<(CredentialMetadataItem, CredentialMetadataItem), SecureStoreError> {
        Ok((
            self.find_named_metadata(keychain, &self.service)?,
            self.find_named_metadata(keychain, &self.migration_service())?,
        ))
    }

    fn find_named_metadata(
        &self,
        keychain: &SecKeychain,
        service: &str,
    ) -> Result<CredentialMetadataItem, SecureStoreError> {
        gocode_macos_keychain_acl::find_generic_password_metadata(keychain, service, &self.account)
            .map_err(map_acl_error)?
            .map(|metadata| {
                ProviderCredentialMetadata::decode(&metadata.bytes)
                    .map(|decoded| (decoded, metadata.item))
            })
            .transpose()
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
        #[cfg(test)]
        PROVIDER_CREDENTIAL_PASSWORD_READS.set(PROVIDER_CREDENTIAL_PASSWORD_READS.get() + 1);
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

fn verify_migration_metadata(
    metadata: &ProviderCredentialMetadata,
    item: &SecKeychainItem,
    access: &ProviderCredentialAccessPolicy,
    exact_access: &ExactKeychainAccess,
) -> Result<(), SecureStoreError> {
    if !metadata.access_matches(access) || metadata.acl_set_digest() != exact_access.digest() {
        return Err(SecureStoreError::CredentialMigrationIncomplete);
    }
    verify_item_acl(item, exact_access.digest())
        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)
}

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
        gocode_macos_keychain_acl::find_generic_password_metadata(&keychain, SERVICE_NAME, &account)
            .map_err(|_| SecureStoreError::Unavailable)
            .map(|metadata| {
                if metadata.is_some() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    struct ProviderCredentialCleanup {
        service: String,
        account: String,
    }

    impl Drop for ProviderCredentialCleanup {
        fn drop(&mut self) {
            let cleanup = [
                format!("{}{PROVIDER_CREDENTIAL_MIGRATION_SUFFIX}", self.service),
                self.service.clone(),
            ]
            .into_iter()
            .try_for_each(|service| {
                match security_framework::passwords::delete_generic_password(
                    &service,
                    &self.account,
                ) {
                    Ok(()) => {}
                    Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => {}
                    Err(error) => return Err(format!("delete {service}: {error}")),
                }
                match security_framework::passwords::get_generic_password(&service, &self.account) {
                    Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
                    Ok(_) => Err(format!("cleanup left {service}")),
                    Err(error) => Err(format!("verify {service}: {error}")),
                }
            });
            if !std::thread::panicking() {
                cleanup.expect("provider credential test cleanup and postcondition");
            }
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

        fn resign_with_distinct_identity(&self) {
            std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700))
                .expect("make executable copy resignable");
            let output = std::process::Command::new("/usr/bin/codesign")
                .args([
                    "--force",
                    "--sign",
                    "-",
                    "--identifier",
                    "dev.gocode.untrusted-keychain-test",
                ])
                .arg(&self.0)
                .output()
                .expect("launch ad-hoc codesign");
            assert!(
                output.status.success(),
                "ad-hoc codesign failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o500))
                .expect("restrict re-signed executable copy");
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

    fn read_child_marker(reader: &mut impl std::io::BufRead, marker: &str) -> std::io::Result<()> {
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("child exited before {marker}"),
                ));
            }
            if line.trim() == marker {
                return Ok(());
            }
        }
    }

    fn seed_incomplete_provider_item(
        store: &MacOsProviderCredentialStore,
        service: &str,
        policy: &ProviderCredentialAccessPolicy,
    ) {
        let exact = ExactKeychainAccess::new(policy.writer_path(), policy.reader_path()).unwrap();
        let metadata =
            ProviderCredentialMetadata::from_access(policy, exact.digest()).encode_incomplete();
        MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            gocode_macos_keychain_acl::create_empty_generic_password(
                keychain,
                service,
                &store.account,
                &metadata,
                &exact,
            )
            .map(|_| ())
            .map_err(map_acl_error)
        })
        .unwrap();
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
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Missing
        );
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &first, &policy)
            .unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &policy)
                .unwrap()
                .with_bytes(<[u8]>::to_vec),
            b"native-test-first"
        );
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &replacement, &policy)
            .unwrap();
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &policy)
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
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Missing
        );
    }

    #[test]
    fn provider_credential_incomplete_enrollment_never_reports_configured_and_can_retry() {
        let (store, _cleanup) = unique_provider_store("incomplete-enrollment");
        let current = std::env::current_exe().expect("current test executable");
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let exact = ExactKeychainAccess::new(&current, &current).unwrap();
        let metadata = ProviderCredentialMetadata::from_access(&policy, exact.digest());
        let credential =
            ProviderCredentialMaterial::new(b"native-test-enrollment-retry".to_vec()).unwrap();
        let encoded =
            StoredProviderCredential::encode(&credential, &policy, exact.digest()).unwrap();

        let failure = MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            create_populated_provider_item(
                keychain,
                &store.service,
                &store.account,
                &metadata,
                &exact,
                &encoded,
                Some(CredentialPopulationFailpoint::EmptyItemWritten),
            )
            .map(|_| ())
        });
        assert_eq!(
            failure,
            Err(SecureStoreError::CredentialEnrollmentIncomplete)
        );

        assert_eq!(
            store.provider_credential_status(ProviderCredentialId::OpenAi, &policy),
            Err(SecureStoreError::CredentialEnrollmentIncomplete)
        );
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        assert_eq!(
            store.migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &policy,
                &replacement_policy,
            ),
            Err(SecureStoreError::CredentialMigrationIncomplete)
        );
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &policy)
            .expect("writer can replace a verified incomplete enrollment");
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &policy)
                .unwrap()
                .with_bytes(<[u8]>::to_vec),
            b"native-test-enrollment-retry"
        );
    }

    #[test]
    fn provider_credential_broad_preseed_never_receives_replacement_material() {
        let (store, _cleanup) = unique_provider_store("broad-preseed");
        let current = std::env::current_exe().expect("current test executable");
        let trusted_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let broad_access = ExactKeychainAccess::new(&current, Path::new("/bin/echo")).unwrap();
        let metadata =
            ProviderCredentialMetadata::from_access(&trusted_policy, broad_access.digest())
                .encode();
        let sentinel = ProviderCredentialMaterial::new(b"native-test-sentinel".to_vec()).unwrap();
        let sentinel_encoded =
            StoredProviderCredential::encode(&sentinel, &trusted_policy, broad_access.digest())
                .unwrap();
        MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            let mut item = gocode_macos_keychain_acl::create_empty_generic_password(
                keychain,
                &store.service,
                &store.account,
                &metadata,
                &broad_access,
            )
            .map_err(map_acl_error)?;
            item.set_password(&sentinel_encoded)
                .map_err(map_keychain_error)
        })
        .unwrap();

        assert_eq!(
            store.provider_credential_status(ProviderCredentialId::OpenAi, &trusted_policy),
            Err(SecureStoreError::CredentialAccessDenied)
        );
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &trusted_policy)
                .unwrap_err(),
            SecureStoreError::CredentialAccessDenied
        );

        let replacement =
            ProviderCredentialMaterial::new(b"native-test-must-not-be-written".to_vec()).unwrap();
        assert_eq!(
            store.store_provider_credential(
                ProviderCredentialId::OpenAi,
                &replacement,
                &trusted_policy,
            ),
            Err(SecureStoreError::CredentialAccessDenied)
        );
        let preserved = MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            let (encoded, _) = keychain
                .find_generic_password(&store.service, &store.account)
                .map_err(map_keychain_error)?;
            StoredProviderCredential::decode(&encoded)
        })
        .unwrap();
        assert_eq!(
            preserved.into_material().with_bytes(<[u8]>::to_vec),
            b"native-test-sentinel"
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
                .load_provider_credential(ProviderCredentialId::OpenAi, &policy)
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
    fn untrusted_process_cannot_read_raw_credential_without_ui() {
        let (store, _cleanup) = unique_provider_store("raw-untrusted-reader");
        let current = std::env::current_exe().expect("current test executable");
        let untrusted = ExecutableCopy::new(&current, "raw-untrusted-reader");
        untrusted.resign_with_distinct_identity();
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-raw-denial".to_vec()).unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &policy)
            .unwrap();

        let mut child = std::process::Command::new(&untrusted.0)
            .args([
                "--exact",
                "macos::tests::untrusted_process_raw_credential_child",
                "--nocapture",
            ])
            .env("GOCODE_RAW_DENIAL_SERVICE", &store.service)
            .env("GOCODE_RAW_DENIAL_ACCOUNT", &store.account)
            .spawn()
            .expect("launch untrusted raw reader");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll untrusted raw reader") {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().expect("kill hung untrusted raw reader");
                let _ = child.wait();
                panic!("untrusted raw reader did not fail closed without UI");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(status.success(), "untrusted raw reader child failed");
    }

    #[test]
    fn untrusted_process_raw_credential_child() {
        let (Some(service), Some(account)) = (
            std::env::var_os("GOCODE_RAW_DENIAL_SERVICE"),
            std::env::var_os("GOCODE_RAW_DENIAL_ACCOUNT"),
        ) else {
            return;
        };
        let service = service.into_string().expect("UTF-8 service");
        let account = account.into_string().expect("UTF-8 account");
        let _interaction_lock =
            SecKeychain::disable_user_interaction().expect("disable Keychain UI");
        let keychain = SecKeychain::default().expect("default Keychain");
        let error = keychain
            .find_generic_password(&service, &account)
            .expect_err("unenrolled process must not read raw credential");
        assert!(
            matches!(
                error.code(),
                ERR_SEC_AUTH_FAILED
                    | ERR_SEC_INTERACTION_NOT_ALLOWED
                    | ERR_SEC_NO_ACCESS_FOR_ITEM
                    | ERR_SEC_INVALID_OWNER_EDIT
            ),
            "unexpected raw denial status: {}",
            error.code()
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
                .provider_credential_status(ProviderCredentialId::OpenAi, &replacement_policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &replacement_policy)
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
            CredentialMigrationFailpoint::BackupEmptyWritten,
            CredentialMigrationFailpoint::BackupWritten,
            CredentialMigrationFailpoint::PrimaryDeleted,
            CredentialMigrationFailpoint::ReplacementEmptyWritten,
            CredentialMigrationFailpoint::ReplacementWritten,
        ] {
            let (store, _cleanup) = unique_provider_store(match failpoint {
                CredentialMigrationFailpoint::BackupEmptyWritten => "recover-after-empty-backup",
                CredentialMigrationFailpoint::BackupWritten => "recover-after-backup",
                CredentialMigrationFailpoint::PrimaryDeleted => "recover-after-delete",
                CredentialMigrationFailpoint::ReplacementEmptyWritten => {
                    "recover-after-empty-replacement"
                }
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

            assert_eq!(
                store.provider_credential_status(ProviderCredentialId::OpenAi, &current_policy),
                Err(SecureStoreError::CredentialMigrationIncomplete)
            );
            assert_eq!(
                store
                    .load_provider_credential(ProviderCredentialId::OpenAi, &current_policy)
                    .unwrap_err(),
                SecureStoreError::CredentialMigrationIncomplete
            );
            assert_eq!(
                store.store_provider_credential(
                    ProviderCredentialId::OpenAi,
                    &credential,
                    &current_policy,
                ),
                Err(SecureStoreError::CredentialMigrationIncomplete)
            );

            let first_recovery = store.migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            );
            if matches!(
                failpoint,
                CredentialMigrationFailpoint::PrimaryDeleted
                    | CredentialMigrationFailpoint::ReplacementEmptyWritten
            ) {
                assert_eq!(
                    first_recovery,
                    Err(SecureStoreError::CredentialMigrationIncomplete)
                );
                store
                    .migrate_provider_credential_access(
                        ProviderCredentialId::OpenAi,
                        &current_policy,
                        &replacement_policy,
                    )
                    .unwrap();
            } else {
                first_recovery.unwrap();
            }
            assert_eq!(
                store
                    .provider_credential_status(ProviderCredentialId::OpenAi, &replacement_policy)
                    .unwrap(),
                ProviderCredentialStatus::Configured
            );
            store
                .delete_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap();
        }
    }

    #[test]
    fn provider_credential_migration_discards_incomplete_backup_after_verifying_primary() {
        let (store, _cleanup) = unique_provider_store("incomplete-backup");
        let current = std::env::current_exe().unwrap();
        let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-incomplete-backup".to_vec()).unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &current_policy)
            .unwrap();
        seed_incomplete_provider_item(&store, &store.migration_service(), &current_policy);

        assert_eq!(
            store.provider_credential_status(ProviderCredentialId::OpenAi, &current_policy),
            Err(SecureStoreError::CredentialMigrationIncomplete)
        );
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &current_policy)
                .unwrap_err(),
            SecureStoreError::CredentialMigrationIncomplete
        );
        assert_eq!(
            store.store_provider_credential(
                ProviderCredentialId::OpenAi,
                &credential,
                &current_policy,
            ),
            Err(SecureStoreError::CredentialMigrationIncomplete)
        );
        store
            .migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            )
            .expect("verified complete primary wins over incomplete backup");
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &replacement_policy,)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();
    }

    #[test]
    fn provider_credential_migration_restores_complete_backup_over_incomplete_replacement() {
        let (store, _cleanup) = unique_provider_store("incomplete-replacement");
        let current = std::env::current_exe().unwrap();
        let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-incomplete-replacement".to_vec())
                .unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &current_policy)
            .unwrap();
        MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            let (encoded, primary) = store
                .find_primary_item(keychain)?
                .expect("complete primary before replacement crash");
            let current_access = ExactKeychainAccess::new(
                current_policy.writer_path(),
                current_policy.reader_path(),
            )
            .map_err(map_acl_error)?;
            let metadata =
                ProviderCredentialMetadata::from_access(&current_policy, current_access.digest());
            create_populated_provider_item(
                keychain,
                &store.migration_service(),
                &store.account,
                &metadata,
                &current_access,
                &encoded,
                None,
            )?;
            gocode_macos_keychain_acl::delete_item(&primary).map_err(map_acl_error)
        })
        .unwrap();
        seed_incomplete_provider_item(&store, &store.service, &replacement_policy);

        assert_eq!(
            store.migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            ),
            Err(SecureStoreError::CredentialMigrationIncomplete)
        );
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &current_policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        store
            .migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            )
            .unwrap();
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();
    }

    #[test]
    fn migration_rejects_broad_primary_before_materializing_its_password() {
        let (store, _cleanup) = unique_provider_store("broad-primary-reconcile");
        let current = std::env::current_exe().unwrap();
        let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-broad-primary".to_vec()).unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &current_policy)
            .unwrap();
        MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            let (encoded, primary) = store
                .find_primary_item(keychain)?
                .expect("complete primary before forged replacement");
            let current_access =
                ExactKeychainAccess::new(&current, &current).map_err(map_acl_error)?;
            let current_metadata =
                ProviderCredentialMetadata::from_access(&current_policy, current_access.digest());
            create_populated_provider_item(
                keychain,
                &store.migration_service(),
                &store.account,
                &current_metadata,
                &current_access,
                &encoded,
                None,
            )?;
            gocode_macos_keychain_acl::delete_item(&primary).map_err(map_acl_error)?;

            let broad_access = ExactKeychainAccess::new(&current, Path::new("/bin/echo"))
                .map_err(map_acl_error)?;
            let broad_metadata =
                ProviderCredentialMetadata::from_access(&current_policy, broad_access.digest());
            let broad_encoded = StoredProviderCredential::encode(
                &credential,
                &current_policy,
                broad_access.digest(),
            )?;
            create_populated_provider_item(
                keychain,
                &store.service,
                &store.account,
                &broad_metadata,
                &broad_access,
                &broad_encoded,
                None,
            )
            .map(|_| ())
        })
        .unwrap();

        PROVIDER_CREDENTIAL_PASSWORD_READS.set(0);
        assert_eq!(
            store.migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            ),
            Err(SecureStoreError::CredentialMigrationIncomplete)
        );
        assert_eq!(
            PROVIDER_CREDENTIAL_PASSWORD_READS.get(),
            1,
            "only the verified backup may be materialized before primary ACL rejection"
        );
    }

    #[test]
    fn provider_credential_delete_is_monotonic_after_every_migration_failpoint() {
        for failpoint in [
            CredentialMigrationFailpoint::BackupEmptyWritten,
            CredentialMigrationFailpoint::BackupWritten,
            CredentialMigrationFailpoint::PrimaryDeleted,
            CredentialMigrationFailpoint::ReplacementEmptyWritten,
            CredentialMigrationFailpoint::ReplacementWritten,
        ] {
            let (store, _cleanup) = unique_provider_store(match failpoint {
                CredentialMigrationFailpoint::BackupEmptyWritten => "delete-after-empty-backup",
                CredentialMigrationFailpoint::BackupWritten => "delete-after-backup",
                CredentialMigrationFailpoint::PrimaryDeleted => "delete-after-primary",
                CredentialMigrationFailpoint::ReplacementEmptyWritten => {
                    "delete-after-empty-replacement"
                }
                CredentialMigrationFailpoint::ReplacementWritten => "delete-after-replacement",
            });
            let current = std::env::current_exe().expect("current test executable");
            let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
            let replacement_policy =
                ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
            let credential =
                ProviderCredentialMaterial::new(b"native-test-monotonic-delete".to_vec()).unwrap();

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

            store
                .delete_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap();
            assert_eq!(
                store
                    .provider_credential_status(ProviderCredentialId::OpenAi, &current_policy)
                    .unwrap(),
                ProviderCredentialStatus::Missing
            );
            assert_eq!(
                store
                    .load_provider_credential(ProviderCredentialId::OpenAi, &current_policy)
                    .unwrap_err(),
                SecureStoreError::ProviderCredentialNotFound
            );
            store
                .delete_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap();
        }
    }

    #[test]
    fn enrolled_daemon_reader_can_query_status_without_loading_credential() {
        let (store, _cleanup) = unique_provider_store("reader-status");
        let current = std::env::current_exe().expect("current test executable");
        let reader = ExecutableCopy::new(&current, "status-reader");
        let policy = ProviderCredentialAccessPolicy::new(&current, &reader.0).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-reader-status".to_vec()).unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &policy)
            .unwrap();

        let output = std::process::Command::new(&reader.0)
            .args([
                "--exact",
                "macos::tests::provider_credential_reader_status_child",
                "--nocapture",
            ])
            .env("GOCODE_PROVIDER_STATUS_SERVICE", &store.service)
            .env("GOCODE_PROVIDER_STATUS_ACCOUNT", &store.account)
            .env("GOCODE_PROVIDER_STATUS_WRITER", &current)
            .output()
            .expect("launch enrolled reader status child");
        assert!(
            output.status.success(),
            "reader status child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn provider_credential_reader_status_child() {
        let (Some(service), Some(account), Some(writer)) = (
            std::env::var_os("GOCODE_PROVIDER_STATUS_SERVICE"),
            std::env::var_os("GOCODE_PROVIDER_STATUS_ACCOUNT"),
            std::env::var_os("GOCODE_PROVIDER_STATUS_WRITER"),
        ) else {
            return;
        };
        let store = MacOsProviderCredentialStore::with_test_item(
            service.into_string().expect("UTF-8 service"),
            account.into_string().expect("UTF-8 account"),
        );
        let current = std::env::current_exe().unwrap();
        let policy = ProviderCredentialAccessPolicy::new(Path::new(&writer), &current).unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
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
        let (store, _cleanup) = unique_provider_store("cross-process-lock");
        let current = std::env::current_exe().expect("current test executable");
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-lock-operation".to_vec()).unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &policy)
            .unwrap();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let child_temp = std::env::temp_dir().join(format!(
            "gocode-provider-lock-child-tmp-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&child_temp).unwrap();
        let process_lock = ProviderCredentialProcessLock::acquire().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "macos::tests::provider_credential_process_lock_child",
                "--nocapture",
            ])
            .env("GOCODE_PROVIDER_LOCK_TEST_CHILD", "1")
            .env("GOCODE_PROVIDER_LOCK_SERVICE", &store.service)
            .env("GOCODE_PROVIDER_LOCK_ACCOUNT", &store.account)
            .env("TMPDIR", &child_temp)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn lock contender");
        let mut child_stdout = BufReader::new(child.stdout.take().unwrap());
        read_child_marker(&mut child_stdout, "READY").unwrap();
        child.stdin.as_mut().unwrap().write_all(b"GO\n").unwrap();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = read_child_marker(&mut child_stdout, "CONFIGURED");
            let _ = acquired_tx.send((result, child_stdout));
        });
        assert!(
            acquired_rx
                .recv_timeout(std::time::Duration::from_millis(500))
                .is_err(),
            "child with a different TMPDIR bypassed the process lock"
        );
        drop(process_lock);
        let (operation, _child_stdout) = acquired_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        operation.unwrap();
        assert!(child.wait().unwrap().success());
        std::fs::remove_dir(child_temp).unwrap();
    }

    #[test]
    fn provider_credential_process_lock_child() {
        if std::env::var_os("GOCODE_PROVIDER_LOCK_TEST_CHILD").is_none() {
            return;
        }
        println!("READY");
        std::io::stdout().flush().unwrap();
        let mut go = String::new();
        std::io::stdin().read_line(&mut go).unwrap();
        assert_eq!(go, "GO\n");
        let service = std::env::var("GOCODE_PROVIDER_LOCK_SERVICE").unwrap();
        let account = std::env::var("GOCODE_PROVIDER_LOCK_ACCOUNT").unwrap();
        let store = MacOsProviderCredentialStore::with_test_item(service, account);
        let current = std::env::current_exe().unwrap();
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        println!("CONFIGURED");
        std::io::stdout().flush().unwrap();
    }
}
