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
