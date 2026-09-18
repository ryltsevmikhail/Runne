use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::CredentialBindingDigest;
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial, SecureStoreError,
};

use super::{CredentialServiceRuntimeGateway, map_host_error, now_unix_millis};

impl ProviderCredentialDispatchMaterializer for CredentialServiceRuntimeGateway {
    fn materialize_active(
        &self,
        read: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        let receipt = CredentialBindingDigest::from_measured(read.effect_receipt_digest())
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        let now = now_unix_millis().map_err(map_host_error)?;
        let (result, missing_epoch) = self.with_session(|session| {
            session
                .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?
                .read_material(
                    &self.runtime,
                    &self.authority.runtime_read_authority(),
                    &self.authority.dispatch_effect_receipt_authority(),
                    read.capability().version_ref().clone(),
                    read.lifecycle(),
                    read.fence(),
                    receipt,
                    now,
                )
        });
        if let Some(epoch) = missing_epoch {
            let _ = self.rejoin.queue(epoch);
        }
        let material = result.map_err(map_host_error)?;
        let mut converted = Err(SecureStoreError::InvalidProviderCredential);
        material.consume(|bytes| {
            converted = ProviderCredentialMaterial::new(bytes.to_vec());
        });
        converted
    }
}
