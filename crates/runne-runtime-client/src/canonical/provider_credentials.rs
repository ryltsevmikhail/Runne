use runne_api::{
    MAX_PROVIDER_CREDENTIAL_BYTES_V1, PROVIDER_CREDENTIAL_CONTROL_CAPABILITY_V1,
    ProviderCredentialProviderV1, ProviderCredentialStatusV1,
};

/// Runtime command identity plus zeroizing provider material.
pub struct PairProviderCredentialRequest {
    pub(crate) identity: CommandIdentity,
    provider: ProviderCredentialProviderV1,
    material: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for PairProviderCredentialRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairProviderCredentialRequest")
            .field("identity", &self.identity)
            .field("provider", &self.provider)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl PairProviderCredentialRequest {
    /// Validates the bounded single-line credential before transport.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRequest` when the credential is empty, oversized, or
    /// contains forbidden control bytes.
    pub fn new(
        identity: CommandIdentity,
        provider: ProviderCredentialProviderV1,
        material: Vec<u8>,
    ) -> Result<Self, RuntimeApiError> {
        if material.is_empty()
            || material.len() > MAX_PROVIDER_CREDENTIAL_BYTES_V1
            || material
                .iter()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        {
            return Err(invalid_request());
        }
        Ok(Self {
            identity,
            provider,
            material: Zeroizing::new(material),
        })
    }
}

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
    /// Stores provider material through the authenticated runtime owner.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure when the runtime
    /// rejects the mutation or the response is malformed.
    pub async fn pair_provider_credential(
        &self,
        request: PairProviderCredentialRequest,
    ) -> Result<ProviderCredentialMutationAckDto, RuntimeApiError> {
        require_capability(self, PROVIDER_CREDENTIAL_CONTROL_CAPABILITY_V1)?;
        let provider = request.provider;
        let body = request.material.as_slice();
        let body = serde_json::to_vec(&ProviderCredentialBodyWire {
            credential: URL_SAFE_NO_PAD.encode(body),
        })
        .map_err(|_| invalid_request())?;
        let response = self
            .command_request(
                self.client
                    .put(self.url(&format!("/v1/providers/{}/credential", provider.as_str()))),
                &request.identity,
            )?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        read_provider_ack(response, provider).await
    }

    /// Deletes provider material through the authenticated runtime owner.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure when the runtime
    /// rejects the mutation or the response is malformed.
    pub async fn revoke_provider_credential(
        &self,
        request: RevokeProviderCredentialRequest,
    ) -> Result<ProviderCredentialMutationAckDto, RuntimeApiError> {
        require_capability(self, PROVIDER_CREDENTIAL_CONTROL_CAPABILITY_V1)?;
        let provider = request.provider;
        let response = self
            .command_request(
                self.client
                    .delete(self.url(&format!("/v1/providers/{}/credential", provider.as_str()))),
                &request.identity,
            )?
            .send()
            .await
            .map_err(map_transport)?;
        read_provider_ack(response, provider).await
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderCredentialBodyWire {
    credential: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderCredentialAckWire {
    provider_id: String,
    status: String,
}

async fn read_provider_ack(
    response: reqwest::Response,
    expected_provider: ProviderCredentialProviderV1,
) -> Result<ProviderCredentialMutationAckDto, RuntimeApiError> {
    let wire: ProviderCredentialAckWire = read_success_json(response, &[202]).await?;
    let provider =
        ProviderCredentialProviderV1::parse(&wire.provider_id).map_err(|_| invalid_response())?;
    if provider != expected_provider {
        return Err(invalid_response());
    }
    let status = match wire.status.as_str() {
        "configured" => ProviderCredentialStatusV1::Configured,
        "missing" => ProviderCredentialStatusV1::Missing,
        "unsupported" => ProviderCredentialStatusV1::Unsupported,
        "access_denied" => ProviderCredentialStatusV1::AccessDenied,
        "identity_mismatch" => ProviderCredentialStatusV1::IdentityMismatch,
        "unavailable" => ProviderCredentialStatusV1::Unavailable,
        _ => return Err(invalid_response()),
    };
    Ok(ProviderCredentialMutationAckDto { provider, status })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_ack_wire_is_closed_and_status_is_bounded() {
        let wire: ProviderCredentialAckWire =
            serde_json::from_str(r#"{"providerId":"openai","status":"configured"}"#)
                .expect("valid provider acknowledgement");
        assert_eq!(wire.provider_id, "openai");
        assert!(
            serde_json::from_str::<ProviderCredentialAckWire>(
                r#"{"providerId":"openai","status":"configured","credential":"secret"}"#
            )
            .is_err()
        );
    }
}
