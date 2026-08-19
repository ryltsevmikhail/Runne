use std::sync::Arc;

use runne_secure_store::{
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialStatus,
    ProviderCredentialStore,
};

use crate::error::DaemonError;

pub(crate) async fn provider_credential_status(
    store: Arc<dyn ProviderCredentialStore>,
    credential_id: ProviderCredentialId,
    access: ProviderCredentialAccessPolicy,
) -> Result<ProviderCredentialStatus, DaemonError> {
    tokio::task::spawn_blocking(move || store.provider_credential_status(credential_id, &access))
        .await
        .map_err(|_| DaemonError::Bootstrap("provider credential status unavailable".into()))?
        .map_err(|_| DaemonError::Bootstrap("provider credential status unavailable".into()))
}
