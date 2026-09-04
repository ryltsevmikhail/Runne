use std::sync::{Mutex, MutexGuard};

#[cfg(test)]
use std::cell::Cell;

use runne_macos_keychain_acl::{
    ExactKeychainAccess, KeychainAclError, ProviderCredentialProcessLock,
};
use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};
use security_framework::os::macos::keychain_item::SecKeychainItem;

use crate::provider_credential::{
    ProviderCredentialMetadata, StoredProviderCredential, generate_provider_credential_source_revision,
    source_update::{
        commit_provider_credential_source_update, committed_provider_credential_source_slot,
        recover_provider_credential_record, ProviderCredentialSourceSlot,
        ProviderCredentialSourceSlotBackend,
    },
};
use crate::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialMaterial, ProviderCredentialSource, ProviderCredentialStatus,
    ProviderCredentialStore, ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial,
    ProviderJournalKeyRef, ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStore,
    SecureStoreError, SecurityAnchorV1, SecurityProfileLock, StoredSecurityAnchor,
    SealedTransactionTag,
};
use runne_provider::{
    CredentialDispatchCapability, CredentialGcClaim, CredentialNativeCreateClaim,
    CredentialVersionRef, NativeCredentialAuthority, NativeCredentialDeletionProof,
};
use zeroize::Zeroizing;

struct NativeSecurityLock { profile: [u8; 32], lock: runne_macos_keychain_acl::SecurityProfileProcessLock }

impl crate::security_anchor::SecurityProfileLockBackend for NativeSecurityLock {
    fn seal(&self, database: [u8; 32], generation: u64, transaction: [u8; 32], previous: [u8; 32]) -> Result<SealedTransactionTag, SecureStoreError> {
        let seal = self.lock.seal(self.profile, database, generation, transaction, previous).map_err(|_| SecureStoreError::Unavailable)?;
        SealedTransactionTag::from_storage(seal.as_bytes().to_vec())
    }
    fn verify(&self, database: [u8; 32], generation: u64, transaction: [u8; 32], previous: [u8; 32], seal: &[u8]) -> Result<(), SecureStoreError> { self.lock.verify(self.profile, database, generation, transaction, previous, seal).map_err(|_| SecureStoreError::InvalidSeal) }
}

const SERVICE_NAME: &str = "runne-ui";
const ACCOUNT_PREFIX: &str = "db_generation";
const SECURITY_ANCHOR_MAGIC: &[u8; 8] = b"GCSA1\0\0\0";
const PROVIDER_JOURNAL_KEY_MAGIC: &[u8; 8] = b"GCPJKV1\0";
const PROVIDER_CREDENTIAL_MIGRATION_SUFFIX: &str = ".migration-backup";
const PROVIDER_CREDENTIAL_SOURCE_ALTERNATE_SUFFIX: &str = ".source-alternate";
const ERR_SEC_AUTH_FAILED: i32 = -25_293;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_NO_ACCESS_FOR_ITEM: i32 = -25_243;
const ERR_SEC_INVALID_OWNER_EDIT: i32 = -25_244;
static KEYCHAIN_INTERACTION_LOCK: Mutex<()> = Mutex::new(());

pub struct KeychainInteractionGuard {
    // Drop this first so UI is restored while both serialization locks remain held.
    _user_interaction: KeychainUserInteractionLock,
    _process: ProviderCredentialProcessLock,
    _interaction: MutexGuard<'static, ()>,
}

pub fn acquire_keychain_interaction_locks() -> Result<KeychainInteractionGuard, ()> {
    // Take the process-reentrant kernel lock only after the process-local mutex;
    // otherwise a sibling can hold it while waiting here and block a child.
    let interaction = KEYCHAIN_INTERACTION_LOCK.lock().map_err(|_| ())?;
    let process = ProviderCredentialProcessLock::acquire().map_err(|_| ())?;
    let user_interaction = SecKeychain::disable_user_interaction().map_err(|_| ())?;
    Ok(KeychainInteractionGuard {
        _user_interaction: user_interaction,
        _process: process,
        _interaction: interaction,
    })
}

include!("active_keychain.inc");
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
    anchor_profile: Option<[u8; 32]>,
}

/// macOS Keychain provider-credential backend with explicit executable ACLs.
///
/// This backend is development/ad-hoc only until signed native identity
/// evidence exists; it makes no Developer ID or notarization claim.
#[derive(Debug)]
pub struct MacOsProviderCredentialStore {
    service: String,
    account: String,
    version_authority: Option<NativeCredentialAuthority>,
}

impl MacOsProviderCredentialStore {
    /// Constructs the fixed production-shaped provider credential item.
    #[must_use]
    pub fn new() -> Self {
        Self {
            service: crate::PROVIDER_CREDENTIAL_SERVICE.to_owned(),
            account: ProviderCredentialId::OpenAi.account().to_owned(),
            version_authority: None,
        }
    }

    /// Constructs the fail-closed backend bound to a lifecycle authority.
    #[must_use]
    pub fn new_versioned(authority: NativeCredentialAuthority) -> Self {
        Self {
            version_authority: Some(authority),
            ..Self::new()
        }
    }

    #[cfg(test)]
    const fn with_test_item(service: String, account: String) -> Self {
        Self {
            service,
            account,
            version_authority: None,
        }
    }

    fn scoped_provider_store(&self, provider: ProviderCredentialId) -> Self {
        let account = if self.account == ProviderCredentialId::OpenAi.account() {
            provider.account().to_owned()
        } else {
            self.account.clone()
        };
        Self {
            service: self.service.clone(),
            account,
            version_authority: self.version_authority.clone(),
        }
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
            anchor_profile: None,
        }
    }

    /// Constructs an anchor backend bound to exactly one profile digest.
    #[must_use]
    pub fn for_security_profile(profile_id: impl AsRef<str>, profile: [u8; 32]) -> Self {
        Self {
            account_name: format!("{ACCOUNT_PREFIX}:{}", profile_id.as_ref()),
            anchor_profile: Some(profile),
        }
    }

    fn require_anchor_lock(&self, lock: &SecurityProfileLock<'_>) -> Result<[u8; 32], SecureStoreError> {
        let profile = self.anchor_profile.ok_or(SecureStoreError::LockMismatch)?;
        if lock.matches(profile) { Ok(profile) } else { Err(SecureStoreError::LockMismatch) }
    }

    fn load_security_anchor(&self) -> Result<StoredSecurityAnchor, SecureStoreError> {
        let _keychain_locks = acquire_keychain_interaction_locks()
            .map_err(|()| SecureStoreError::Unavailable)?;
        let keychain = active_keychain().map_err(|()| SecureStoreError::Unavailable)?;
        match keychain.find_generic_password(SERVICE_NAME, &self.account_name) {
            Ok((value, _)) if value.len() == 8 => {
                let generation = decode_anchor(&value)?;
                if generation == 0 { Err(SecureStoreError::CorruptAnchor) } else { Ok(StoredSecurityAnchor::LegacyGeneration(generation)) }
            }
            Ok((value, _)) => decode_security_anchor(&value).map(StoredSecurityAnchor::V1),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(StoredSecurityAnchor::Missing),
            Err(_) => Err(SecureStoreError::Unavailable),
        }
    }

    fn save_security_anchor(&self, anchor: &SecurityAnchorV1) -> Result<(), SecureStoreError> {
        let _keychain_locks = acquire_keychain_interaction_locks()
            .map_err(|()| SecureStoreError::Unavailable)?;
        let encoded = encode_security_anchor(anchor);
        active_keychain().map_err(|()| SecureStoreError::Unavailable)?
            .set_generic_password(SERVICE_NAME, &self.account_name, &encoded)
            .map_err(|_| SecureStoreError::OperationFailed("security anchor keychain write".into()))
    }

    #[cfg(test)]
    fn store_anchor(&self, generation: u64) -> Result<(), SecureStoreError> {
        let _keychain_locks = acquire_keychain_interaction_locks()
            .map_err(|()| SecureStoreError::Unavailable)?;
        let value = generation.to_le_bytes();
        active_keychain().map_err(|()| SecureStoreError::Unavailable)?
            .set_generic_password(SERVICE_NAME, &self.account_name, &value)
            .map_err(|_| SecureStoreError::OperationFailed("legacy anchor keychain write".into()))
    }

    #[cfg(test)]
    fn read_anchor(&self) -> Result<Option<u64>, SecureStoreError> {
        match self.load_security_anchor()? {
            StoredSecurityAnchor::Missing => Ok(None),
            StoredSecurityAnchor::LegacyGeneration(generation) => Ok(Some(generation)),
            StoredSecurityAnchor::V1(_) => Err(SecureStoreError::Unavailable),
        }
    }

    #[cfg(test)]
    fn delete_anchor(&self) -> Result<(), SecureStoreError> {
        let _keychain_locks = acquire_keychain_interaction_locks()
            .map_err(|()| SecureStoreError::Unavailable)?;
        let keychain = active_keychain().map_err(|()| SecureStoreError::Unavailable)?;
        match keychain.find_generic_password(SERVICE_NAME, &self.account_name) {
            Ok((_, item)) => runne_macos_keychain_acl::delete_item(&item)
                .map_err(|_| SecureStoreError::Unavailable),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(_) => Err(SecureStoreError::Unavailable),
        }
    }

    pub(crate) fn provider_recovery_profile_scope(&self) -> &str {
        &self.account_name
    }
}

impl SecureStore for MacOsKeychainStore {
    fn acquire_security_profile_lock(&self, profile: [u8; 32]) -> Result<SecurityProfileLock<'_>, SecureStoreError> {
        if self.anchor_profile != Some(profile) { return Err(SecureStoreError::LockMismatch); }
        let lock = runne_macos_keychain_acl::SecurityProfileProcessLock::acquire(profile).map_err(|_| SecureStoreError::Unavailable)?;
        Ok(SecurityProfileLock::new(profile, NativeSecurityLock { profile, lock }))
    }
    fn read_security_anchor(&self, lock: &SecurityProfileLock<'_>) -> Result<StoredSecurityAnchor, SecureStoreError> {
        self.require_anchor_lock(lock)?;
        self.load_security_anchor()
    }
    fn compare_and_advance_anchor(&self, lock: &SecurityProfileLock<'_>, expected: &SecurityAnchorV1, next: &SecurityAnchorV1) -> Result<(), SecureStoreError> {
        let profile = self.require_anchor_lock(lock)?;
        if expected.profile_identity_digest != profile || next.profile_identity_digest != profile || !next.is_valid() || next.database_identity != expected.database_identity || expected.generation.checked_add(1) != Some(next.generation) || next.previous_anchor_digest != expected.digest() { return Err(SecureStoreError::InvalidTransition); }
        self.verify_security_transaction(lock, next)?;
        if self.load_security_anchor()? != StoredSecurityAnchor::V1(expected.clone()) { return Err(SecureStoreError::AnchorConflict); }
        self.save_security_anchor(next)?;
        if self.load_security_anchor()? != StoredSecurityAnchor::V1(next.clone()) { return Err(SecureStoreError::AnchorConflict); }
        Ok(())
    }
    fn initialize_security_anchor(&self, lock: &SecurityProfileLock<'_>, next: &SecurityAnchorV1) -> Result<(), SecureStoreError> {
        let profile = self.require_anchor_lock(lock)?;
        if next.profile_identity_digest != profile || !next.is_valid() || next.generation != 1 || next.previous_anchor_digest != [0; 32] { return Err(SecureStoreError::InvalidTransition); }
        self.verify_security_transaction(lock, next)?;
        if self.load_security_anchor()? != StoredSecurityAnchor::Missing { return Err(SecureStoreError::AnchorConflict); }
        self.save_security_anchor(next)
    }
    fn compare_and_migrate_legacy_anchor(&self, lock: &SecurityProfileLock<'_>, expected: u64, next: &SecurityAnchorV1) -> Result<(), SecureStoreError> {
        let profile = self.require_anchor_lock(lock)?;
        if next.profile_identity_digest != profile || !next.is_valid() || expected.checked_add(1) != Some(next.generation) { return Err(SecureStoreError::InvalidTransition); }
        self.verify_security_transaction(lock, next)?;
        if self.load_security_anchor()? != StoredSecurityAnchor::LegacyGeneration(expected) { return Err(SecureStoreError::AnchorConflict); }
        self.save_security_anchor(next)
    }
    fn seal_security_transaction(&self, lock: &SecurityProfileLock<'_>, database: [u8; 32], generation: u64, digest: [u8; 32], previous: [u8; 32]) -> Result<SealedTransactionTag, SecureStoreError> {
        self.require_anchor_lock(lock)?;
        lock.seal(database, generation, digest, previous)
    }
    fn verify_security_transaction(&self, lock: &SecurityProfileLock<'_>, anchor: &SecurityAnchorV1) -> Result<(), SecureStoreError> {
        let profile = self.require_anchor_lock(lock)?;
        if anchor.profile_identity_digest != profile || !anchor.is_valid() { return Err(SecureStoreError::InvalidTransition); }
        lock.verify(anchor.database_identity, anchor.generation, anchor.transaction_digest, anchor.previous_anchor_digest, anchor.sealed_transaction.bytes())
    }
}
