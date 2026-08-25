use zeroize::Zeroizing;

use crate::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};

use super::NativeKeyringStore;

const SERVICE: &str = "dev.runne.provider-journal-key.v1";
const MAGIC: &[u8; 8] = b"GCPJKV1\0";

impl ProviderJournalKeyring for NativeKeyringStore {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn provider_journal_key_status(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        let (service, account) = service_account(self, key_ref);
        Self::read_secret(&service, &account).map(|value| {
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
        let key_ref = key.key_ref();
        let (service, account) = service_account(self, key_ref);
        if let Some(existing) = Self::read_secret(&service, &account)? {
            let existing = decode(&existing, key_ref)?;
            return existing.with_bytes(|old| {
                key.with_bytes(|new| {
                    if old == new {
                        Ok(())
                    } else {
                        Err(SecureStoreError::CorruptProviderJournalKey)
                    }
                })
            });
        }
        Self::write_secret(&service, &account, &encode(key))
    }

    fn load_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        let (service, account) = service_account(self, key_ref);
        let encoded = Self::read_secret(&service, &account)?
            .ok_or(SecureStoreError::ProviderJournalKeyNotFound)?;
        decode(&encoded, key_ref)
    }

    fn delete_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
        _proof: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        let (service, account) = service_account(self, key_ref);
        if Self::read_secret(&service, &account)?.is_none() {
            return Err(SecureStoreError::ProviderJournalKeyNotFound);
        }
        Self::delete_secret(&service, &account)
    }
}

fn service_account(store: &NativeKeyringStore, key_ref: ProviderJournalKeyRef) -> (String, String) {
    (
        SERVICE.to_owned(),
        format!(
            "{}:{}:{}:{}:{}",
            store.profile_id,
            encode_hex(&key_ref.key_id()),
            key_ref.version(),
            encode_hex(&key_ref.runtime_authority_id()),
            key_ref.database_generation(),
        ),
    )
}

fn encode(key: &ProviderJournalKeyMaterial) -> Zeroizing<Vec<u8>> {
    let key_ref = key.key_ref();
    let mut encoded = Zeroizing::new(Vec::with_capacity(88));
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&key_ref.key_id());
    encoded.extend_from_slice(&key_ref.version().to_be_bytes());
    encoded.extend_from_slice(&key_ref.runtime_authority_id());
    encoded.extend_from_slice(&key_ref.database_generation().to_be_bytes());
    key.with_bytes(|bytes| encoded.extend_from_slice(bytes));
    encoded
}

fn decode(
    encoded: &[u8],
    expected: ProviderJournalKeyRef,
) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
    if encoded.len() != 88 || encoded.get(..8) != Some(MAGIC) {
        return Err(SecureStoreError::CorruptProviderJournalKey);
    }
    let actual = ProviderJournalKeyRef::new(
        fixed::<16>(&encoded[8..24])?,
        u64::from_be_bytes(fixed::<8>(&encoded[24..32])?),
        fixed::<16>(&encoded[32..48])?,
        u64::from_be_bytes(fixed::<8>(&encoded[48..56])?),
    )?;
    if actual != expected {
        return Err(SecureStoreError::CorruptProviderJournalKey);
    }
    ProviderJournalKeyMaterial::new(actual, fixed::<32>(&encoded[56..88])?)
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], SecureStoreError> {
    bytes
        .try_into()
        .map_err(|_| SecureStoreError::CorruptProviderJournalKey)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
