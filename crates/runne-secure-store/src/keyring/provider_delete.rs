use zeroize::Zeroizing;

use crate::SecureStoreError;
use crate::provider_credential::{ProviderCredentialAccessPolicy, StoredProviderCredential};

use super::provider::validate_stored;

pub(super) fn delete_provider_record_with(
    access: &ProviderCredentialAccessPolicy,
    read: impl FnOnce() -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError>,
    delete: impl FnOnce() -> Result<(), SecureStoreError>,
) -> Result<(), SecureStoreError> {
    access.validate_writer_current()?;
    let encoded = read()?.ok_or(SecureStoreError::ProviderCredentialNotFound)?;
    let stored = StoredProviderCredential::decode(&encoded)?;
    validate_stored(&stored, access)?;
    stored.validate_delete_access(access, super::provider::access_digest(access))?;
    access.remeasure()?;
    delete()
}
