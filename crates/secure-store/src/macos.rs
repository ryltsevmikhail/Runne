use crate::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyring, SecureStore, SecureStoreError,
};
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "gocode-ui";
const ACCOUNT_PREFIX: &str = "db_generation";
const PROVIDER_JOURNAL_KEY_MAGIC: &[u8; 8] = b"GCPJKV1\0";

pub struct MacOsKeychainStore {
    account_name: String,
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
}
