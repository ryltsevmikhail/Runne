impl AppCore {
    /// Returns the authenticated runtime's metadata-only provider projection.
    ///
    /// Provider credentials, secure-store errors, endpoint material and paths
    /// never cross this application boundary.
    ///
    /// # Errors
    ///
    /// Returns a closed error when no authenticated runtime projection exists.
    pub fn provider_statuses(&self) -> Result<Vec<ProviderStatusSnapshotV1>, AppCoreError> {
        let client = self
            .runtime_client()?
            .ok_or(AppCoreError::RuntimeUnavailable)?;
        let statuses = client.provider_statuses();
        if statuses.is_empty() {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        Ok(statuses.to_vec())
    }

    /// Stores provider material through the authenticated runtime owner.
    ///
    /// # Errors
    ///
    /// Returns a closed validation, runtime or transport error.
    pub async fn pair_provider_credential(
        &self,
        provider: &str,
        material: Vec<u8>,
    ) -> Result<CanonicalProviderCredentialMutation, AppCoreError> {
        let provider = runne_api::ProviderCredentialProviderV1::parse(provider)
            .map_err(|_| AppCoreError::InvalidMutation)?;
        let request = runne_runtime_client::PairProviderCredentialRequest::new(
            process_command_identity()?,
            provider,
            material,
        )
        .map_err(|_| AppCoreError::InvalidMutation)?;
        let _operation = self.runtime_operation.lock().await;
        let ack = self
            .live_runtime_client()?
            .pair_provider_credential(request)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalProviderCredentialMutation::from(ack))
    }

    /// Removes provider material through the authenticated runtime owner.
    ///
    /// # Errors
    ///
    /// Returns a closed validation, runtime or transport error.
    pub async fn revoke_provider_credential(
        &self,
        provider: &str,
    ) -> Result<CanonicalProviderCredentialMutation, AppCoreError> {
        let provider = runne_api::ProviderCredentialProviderV1::parse(provider)
            .map_err(|_| AppCoreError::InvalidMutation)?;
        let request = runne_runtime_client::RevokeProviderCredentialRequest::new(
            process_command_identity()?,
            provider,
        );
        let _operation = self.runtime_operation.lock().await;
        let ack = self
            .live_runtime_client()?
            .revoke_provider_credential(request)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalProviderCredentialMutation::from(ack))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalProviderCredentialMutation {
    pub provider_id: &'static str,
    pub status: &'static str,
}

impl From<runne_runtime_client::ProviderCredentialMutationAckDto>
    for CanonicalProviderCredentialMutation
{
    fn from(value: runne_runtime_client::ProviderCredentialMutationAckDto) -> Self {
        Self {
            provider_id: value.provider().as_str(),
            status: match value.status() {
                runne_api::ProviderCredentialStatusV1::Configured => "configured",
                runne_api::ProviderCredentialStatusV1::Missing => "missing",
                runne_api::ProviderCredentialStatusV1::Unsupported => "unsupported",
                runne_api::ProviderCredentialStatusV1::AccessDenied => "access_denied",
                runne_api::ProviderCredentialStatusV1::IdentityMismatch => "identity_mismatch",
                runne_api::ProviderCredentialStatusV1::Unavailable => "unavailable",
            },
        }
    }
}
