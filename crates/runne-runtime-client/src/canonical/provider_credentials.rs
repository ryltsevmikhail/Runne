use runne_api::{ProviderCredentialProviderV1, ProviderCredentialStatusV1};

/// Runtime command identity for provider credential deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeProviderCredentialRequest {
    pub(crate) identity: CommandIdentity,
    provider: ProviderCredentialProviderV1,
}

impl RevokeProviderCredentialRequest {
    #[must_use]
    pub const fn new(identity: CommandIdentity, provider: ProviderCredentialProviderV1) -> Self {
        Self { identity, provider }
    }
}

/// Safe acknowledgement from the runtime credential owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCredentialMutationAckDto {
    provider: ProviderCredentialProviderV1,
    status: ProviderCredentialStatusV1,
}

impl ProviderCredentialMutationAckDto {
    #[must_use]
    pub const fn provider(self) -> ProviderCredentialProviderV1 {
        self.provider
    }

    #[must_use]
    pub const fn status(self) -> ProviderCredentialStatusV1 {
        self.status
    }
}

impl AuthenticatedRuntimeClient {
    /// Returns the closed V1 compatibility disposition.
    ///
    /// # Errors
    ///
    /// V1 mutation transport is permanently unavailable. Consumers must use
    /// the protected V2 enrollment flow once its qualified profile is available.
    #[expect(
        clippy::unused_async,
        reason = "legacy compatibility preserves the published asynchronous client API"
    )]
    pub async fn revoke_provider_credential(
        &self,
        _request: RevokeProviderCredentialRequest,
    ) -> Result<ProviderCredentialMutationAckDto, RuntimeApiError> {
        Err(legacy_control_closed())
    }
}

const fn legacy_control_closed() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn legacy_mutations_are_closed_before_transport() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let client = test_client(listener.local_addr().expect("listener address"));
        let identity = CommandIdentity::new(CanonicalId::now_v7(), "legacy-control")
            .expect("command identity");
        let provider = ProviderCredentialProviderV1::parse("openai").expect("provider");
        assert_eq!(
            client
                .revoke_provider_credential(RevokeProviderCredentialRequest::new(
                    identity, provider
                ))
                .await
                .expect_err("legacy revoke is closed")
                .kind(),
            RuntimeApiErrorKind::Unavailable
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "legacy mutation opened a transport connection"
        );
    }

    fn test_client(address: std::net::SocketAddr) -> AuthenticatedRuntimeClient {
        AuthenticatedRuntimeClient::from_protected_bundled_session(
            reqwest::Client::builder()
                .timeout(Duration::from_millis(50))
                .build()
                .expect("client"),
            format!("http://{address}"),
            RuntimeSessionAuthority::from_local_session([7; 32]),
            RuntimeSessionInfo {
                profile_id: crate::EXPECTED_BUNDLE_ID.to_owned(),
                schema_hash: crate::GOLDEN_BUNDLE_HASH.to_owned(),
                runtime_version: "test".to_owned(),
                capabilities: PROTECTED_RUNTIME_CAPABILITIES
                    .iter()
                    .map(|capability| (*capability).to_owned())
                    .collect(),
                authority_id: "authority".to_owned(),
                principal_id: "principal".to_owned(),
                event_log_lineage_id: "lineage".to_owned(),
                daemon_instance_id: "daemon".to_owned(),
                launch_generation: 1,
                session_id: "session".to_owned(),
                authorization_epoch: 1,
                sensitivity_ceiling: "sensitive".to_owned(),
                certificate_sha256: "certificate".to_owned(),
                capability_digest: "digest".to_owned(),
            },
            Vec::new(),
        )
    }
}
