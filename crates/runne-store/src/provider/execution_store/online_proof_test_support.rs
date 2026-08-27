use runne_application::provider::{ProviderExecutionStore, ProviderJournalKeyBinding};
use runne_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};
use std::sync::{Arc, Barrier};

pub(super) struct TestKeyring {
    keys: Vec<(ProviderJournalKeyRef, [u8; 32])>,
    load_gate: Option<(u64, Arc<Barrier>, Arc<Barrier>)>,
}

impl TestKeyring {
    pub(super) fn new(keys: impl IntoIterator<Item = (u64, [u8; 32])>) -> Self {
        Self::for_authority(keys, [1; 16], 7)
    }

    pub(super) fn for_authority(
        keys: impl IntoIterator<Item = (u64, [u8; 32])>,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
    ) -> Self {
        Self {
            keys: keys
                .into_iter()
                .map(|(version, bytes)| {
                    (
                        ProviderJournalKeyRef::new(
                            [9; 16],
                            version,
                            runtime_authority_id,
                            database_generation,
                        )
                        .unwrap(),
                        bytes,
                    )
                })
                .collect(),
            load_gate: None,
        }
    }

    pub(super) fn block_on_load(
        mut self,
        version: u64,
        reached: Arc<Barrier>,
        release: Arc<Barrier>,
    ) -> Self {
        self.load_gate = Some((version, reached, release));
        self
    }
}
impl ProviderJournalKeyring for TestKeyring {
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
        if let Some((version, reached, release)) = &self.load_gate
            && key.version() == *version
        {
            reached.wait();
            release.wait();
        }
        self.keys
            .iter()
            .find(|(stored, _)| *stored == key)
            .map(|(_, bytes)| ProviderJournalKeyMaterial::new(key, *bytes).unwrap())
            .ok_or(SecureStoreError::ProviderJournalKeyNotFound)
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
        Ok(if self.keys.iter().any(|(stored, _)| *stored == key) {
            ProviderJournalKeyStatus::Available
        } else {
            ProviderJournalKeyStatus::Missing
        })
    }
}
pub(super) fn arm(store: &super::SqliteProviderExecutionStore) {
    arm_for_authority(store, [1; 16], 7);
}

pub(super) fn arm_for_authority(
    store: &super::SqliteProviderExecutionStore,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
) {
    let keyring =
        TestKeyring::for_authority([(1, [7; 32])], runtime_authority_id, database_generation);
    let binding =
        ProviderJournalKeyBinding::new([9; 16], 1, runtime_authority_id, database_generation)
            .unwrap();
    store
        .activate_journal_key_with_keyring(&keyring, binding)
        .unwrap();
    store
        .install_online_effect_proof_capability(&keyring, binding)
        .unwrap();
}

pub(super) fn install_with(
    store: &super::SqliteProviderExecutionStore,
    active_version: u64,
    keys: impl IntoIterator<Item = (u64, [u8; 32])>,
) {
    let binding = ProviderJournalKeyBinding::new([9; 16], active_version, [1; 16], 7).unwrap();
    let keyring = TestKeyring::new(keys);
    store
        .install_online_effect_proof_capability(&keyring, binding)
        .unwrap();
}
