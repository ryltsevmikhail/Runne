use crate::{SecureStore, SecureStoreError};

const SERVICE_NAME: &str = "gocode-ui";
const ACCOUNT_PREFIX: &str = "db_generation";

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

fn decode_anchor(bytes: &[u8]) -> Result<u64, SecureStoreError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| SecureStoreError::CorruptAnchor)?;
    Ok(u64::from_le_bytes(bytes))
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
}
