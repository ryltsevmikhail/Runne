use runne_application::provider::{ProviderExecutionStore, ProviderJournalKeyBinding};
use runne_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};
use runne_store::provider::SqliteProviderExecutionStore;

#[allow(dead_code)]
struct FixedKeyring {
    keys: Vec<ProviderJournalKeyRef>,
}

impl ProviderJournalKeyring for FixedKeyring {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn store_provider_journal_key(
        &self,
        _: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        Ok(())
    }

    fn load_provider_journal_key(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        if self.keys.contains(&key) {
            ProviderJournalKeyMaterial::new(key, [7; 32])
        } else {
            Err(SecureStoreError::ProviderJournalKeyNotFound)
        }
    }

    fn delete_provider_journal_key(
        &self,
        _: ProviderJournalKeyRef,
        _: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::DeletionDenied)
    }

    fn provider_journal_key_status(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        Ok(if self.keys.contains(&key) {
            ProviderJournalKeyStatus::Available
        } else {
            ProviderJournalKeyStatus::Missing
        })
    }
}

#[allow(dead_code)]
pub(super) fn arm(store: &SqliteProviderExecutionStore, database_generation: u64) {
    let key = ProviderJournalKeyRef::new([9; 16], 1, [1; 16], database_generation).unwrap();
    let keyring = FixedKeyring { keys: vec![key] };
    let _ = arm_with_keyring(store, &keyring, database_generation);
}

// Integration targets compile this shared fixture independently.
#[allow(dead_code)]
pub(super) fn activate(store: &SqliteProviderExecutionStore, binding: ProviderJournalKeyBinding) {
    let key = ProviderJournalKeyRef::new(
        binding.key_id(),
        binding.key_version(),
        binding.runtime_authority_id(),
        binding.database_generation(),
    )
    .unwrap();
    let keyring = FixedKeyring { keys: vec![key] };
    store
        .activate_journal_key_with_keyring(&keyring, binding)
        .unwrap();
}

#[allow(dead_code)]
pub(super) fn arm_binding(
    store: &SqliteProviderExecutionStore,
    binding: ProviderJournalKeyBinding,
) {
    let key = ProviderJournalKeyRef::new(
        binding.key_id(),
        binding.key_version(),
        binding.runtime_authority_id(),
        binding.database_generation(),
    )
    .unwrap();
    let keyring = FixedKeyring { keys: vec![key] };
    store
        .activate_journal_key_with_keyring(&keyring, binding)
        .unwrap();
    store
        .install_online_effect_proof_capability(&keyring, binding)
        .unwrap();
}

#[allow(dead_code)]
pub(super) fn rotate(
    store: &SqliteProviderExecutionStore,
    existing: ProviderJournalKeyBinding,
    replacement: ProviderJournalKeyBinding,
) {
    let keys = [existing, replacement]
        .into_iter()
        .map(|binding| {
            ProviderJournalKeyRef::new(
                binding.key_id(),
                binding.key_version(),
                binding.runtime_authority_id(),
                binding.database_generation(),
            )
            .unwrap()
        })
        .collect();
    let keyring = FixedKeyring { keys };
    store
        .activate_journal_key_with_keyring(&keyring, replacement)
        .unwrap();
}

pub(super) fn arm_with_keyring(
    store: &SqliteProviderExecutionStore,
    keyring: &dyn ProviderJournalKeyring,
    database_generation: u64,
) -> ProviderJournalKeyBinding {
    let key = ProviderJournalKeyRef::new([9; 16], 1, [1; 16], database_generation).unwrap();
    let binding = ProviderJournalKeyBinding::new([9; 16], 1, [1; 16], database_generation).unwrap();
    keyring
        .store_provider_journal_key(&ProviderJournalKeyMaterial::new(key, [7; 32]).unwrap())
        .unwrap();
    store
        .activate_journal_key_with_keyring(keyring, binding)
        .unwrap();
    store
        .install_online_effect_proof_capability(keyring, binding)
        .unwrap();
    binding
}
