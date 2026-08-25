//! Runtime-owned provider credential mutation adapter.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use runne_api::{
    ProviderCredentialCommandContext, ProviderCredentialControlHostPort,
    ProviderCredentialHostError, ProviderCredentialMutationAckV1, ProviderCredentialPairCommand,
    ProviderCredentialProviderV1, ProviderCredentialRevokeCommand, ProviderCredentialStatusV1,
};
use runne_secure_store::{
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialMaterial,
    ProviderCredentialStore, SecureStoreError,
};

const LOCAL_PRINCIPAL: &str = "local-owner";
const DAEMON_ACTOR: &str = "runne-daemon";

/// Adapts the native secure store to the authenticated runtime HTTP port.
#[derive(Clone)]
pub(crate) struct DaemonProviderCredentialControl {
    store: Arc<dyn ProviderCredentialStore>,
    access: Option<ProviderCredentialAccessPolicy>,
}

impl DaemonProviderCredentialControl {
    #[must_use]
    pub(crate) fn new(
        store: Arc<dyn ProviderCredentialStore>,
        access: Option<ProviderCredentialAccessPolicy>,
    ) -> Self {
        Self { store, access }
    }

    fn authorize(
        context: &ProviderCredentialCommandContext,
    ) -> Result<(), ProviderCredentialHostError> {
        if context.principal.as_str() != LOCAL_PRINCIPAL || context.actor.as_str() != DAEMON_ACTOR {
            return Err(ProviderCredentialHostError::Forbidden);
        }
        Ok(())
    }
}

impl ProviderCredentialControlHostPort for DaemonProviderCredentialControl {
    fn pair_provider_credential<'a>(
        &'a self,
        context: ProviderCredentialCommandContext,
        command: ProviderCredentialPairCommand,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<ProviderCredentialMutationAckV1, ProviderCredentialHostError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Self::authorize(&context)?;
            let access = self
                .access
                .clone()
                .ok_or(ProviderCredentialHostError::Unavailable)?;
            let provider = command.provider();
            let provider_id = provider_id(provider);
            let store = Arc::clone(&self.store);
            tokio::task::spawn_blocking(move || {
                command.with_material(|bytes| {
                    let material =
                        ProviderCredentialMaterial::new(bytes.to_vec()).map_err(map_store_error)?;
                    store
                        .store_provider_credential(provider_id, &material, &access)
                        .map_err(map_store_error)
                })
            })
            .await
            .map_err(|_| ProviderCredentialHostError::Unavailable)??;
            Ok(ProviderCredentialMutationAckV1::new(
                provider,
                ProviderCredentialStatusV1::Configured,
            ))
        })
    }

    fn revoke_provider_credential<'a>(
        &'a self,
        context: ProviderCredentialCommandContext,
        command: ProviderCredentialRevokeCommand,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<ProviderCredentialMutationAckV1, ProviderCredentialHostError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Self::authorize(&context)?;
            let access = self
                .access
                .clone()
                .ok_or(ProviderCredentialHostError::Unavailable)?;
            let provider = command.provider();
            let provider_id = provider_id(provider);
            let store = Arc::clone(&self.store);
            let result = tokio::task::spawn_blocking(move || {
                store.delete_provider_credential(provider_id, &access)
            })
            .await
            .map_err(|_| ProviderCredentialHostError::Unavailable)?;
            match result {
                Ok(()) | Err(SecureStoreError::ProviderCredentialNotFound) => {
                    Ok(ProviderCredentialMutationAckV1::new(
                        provider,
                        ProviderCredentialStatusV1::Missing,
                    ))
                }
                Err(error) => Err(map_store_error(error)),
            }
        })
    }
}

fn provider_id(provider: ProviderCredentialProviderV1) -> ProviderCredentialId {
    match provider {
        ProviderCredentialProviderV1::OpenAi => ProviderCredentialId::OpenAi,
        ProviderCredentialProviderV1::DeepSeek => ProviderCredentialId::DeepSeek,
    }
}

fn map_store_error(error: SecureStoreError) -> ProviderCredentialHostError {
    match error {
        SecureStoreError::InvalidProviderCredential => ProviderCredentialHostError::InvalidRequest,
        SecureStoreError::CredentialAccessDenied
        | SecureStoreError::CredentialIdentityMismatch
        | SecureStoreError::CredentialAclMigrationRequired => {
            ProviderCredentialHostError::Forbidden
        }
        SecureStoreError::UnsupportedSecureStoreBackend => ProviderCredentialHostError::Unsupported,
        SecureStoreError::ProviderCredentialNotFound => ProviderCredentialHostError::Unavailable,
        SecureStoreError::ProviderCredentialOperationFailed
        | SecureStoreError::Unavailable
        | SecureStoreError::CredentialEnrollmentIncomplete
        | SecureStoreError::CredentialMigrationIncomplete
        | SecureStoreError::ProviderCredentialSourceRevisionUnavailable
        | SecureStoreError::CorruptProviderCredential => ProviderCredentialHostError::Unavailable,
        _ => ProviderCredentialHostError::InvariantViolation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_api::{ApiActor, ApiPrincipalId, ProviderCredentialCommandContext};
    use runne_domain::id::{CommandId, IdempotencyKey};

    #[test]
    fn rejects_non_local_owner_context_without_touching_store() {
        let context = ProviderCredentialCommandContext {
            command_id: "018f2e3a-7000-7000-8000-000000000003"
                .parse::<CommandId>()
                .unwrap(),
            idempotency_key: IdempotencyKey::new("provider-1").unwrap(),
            principal: ApiPrincipalId::new("external").unwrap(),
            actor: ApiActor::new(DAEMON_ACTOR).unwrap(),
        };
        assert_eq!(
            DaemonProviderCredentialControl::authorize(&context),
            Err(ProviderCredentialHostError::Forbidden)
        );
    }
}
