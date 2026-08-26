//! Fail-closed V1 provider credential compatibility host.

use std::future::Future;
use std::pin::Pin;

use runne_api::{
    ProviderCredentialCommandContext, ProviderCredentialControlHostPort,
    ProviderCredentialHostError, ProviderCredentialMutationAckV1, ProviderCredentialPairCommand,
    ProviderCredentialRevokeCommand,
};

/// Keeps the legacy host port reachable without retaining any native store authority.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DaemonProviderCredentialControl;

impl DaemonProviderCredentialControl {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl ProviderCredentialControlHostPort for DaemonProviderCredentialControl {
    fn pair_provider_credential<'a>(
        &'a self,
        _context: ProviderCredentialCommandContext,
        _command: ProviderCredentialPairCommand,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<ProviderCredentialMutationAckV1, ProviderCredentialHostError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(ProviderCredentialHostError::Unsupported) })
    }

    fn revoke_provider_credential<'a>(
        &'a self,
        _context: ProviderCredentialCommandContext,
        _command: ProviderCredentialRevokeCommand,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<ProviderCredentialMutationAckV1, ProviderCredentialHostError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(ProviderCredentialHostError::Unsupported) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_api::{
        ApiActor, ApiPrincipalId, ProviderCredentialProviderV1, ProviderCredentialRevokeCommand,
    };
    use runne_domain::id::{CommandId, IdempotencyKey};

    #[tokio::test]
    async fn v1_pair_and_revoke_are_always_unsupported() {
        let host = DaemonProviderCredentialControl::new();
        let pair = ProviderCredentialPairCommand::new(
            ProviderCredentialProviderV1::OpenAi,
            b"must-never-reach-a-store".to_vec(),
        )
        .unwrap();

        assert_eq!(
            host.pair_provider_credential(context("local-owner"), pair)
                .await,
            Err(ProviderCredentialHostError::Unsupported)
        );
        assert_eq!(
            host.revoke_provider_credential(
                context("external"),
                ProviderCredentialRevokeCommand::new(ProviderCredentialProviderV1::OpenAi),
            )
            .await,
            Err(ProviderCredentialHostError::Unsupported)
        );
    }

    #[test]
    fn v1_host_source_has_no_native_store_or_material_ingress() {
        const SOURCE: &str = include_str!("provider_credential_control.rs");
        for prohibited in [
            concat!("runne_", "secure_store"),
            concat!("ProviderCredential", "Store"),
            concat!("with_", "material"),
            concat!("store_provider_", "credential"),
            concat!("delete_provider_", "credential"),
        ] {
            assert!(
                !SOURCE.contains(prohibited),
                "prohibited V1 ingress: {prohibited}"
            );
        }
    }

    fn context(principal: &str) -> ProviderCredentialCommandContext {
        ProviderCredentialCommandContext {
            command_id: CommandId::from_bytes([7; 16]),
            idempotency_key: IdempotencyKey::new("closed-v1").unwrap(),
            principal: ApiPrincipalId::new(principal).unwrap(),
            actor: ApiActor::new("runne-daemon").unwrap(),
        }
    }
}
