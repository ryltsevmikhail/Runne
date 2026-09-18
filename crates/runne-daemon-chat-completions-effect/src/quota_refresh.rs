use crate::quota_refresh_transport::QuotaRefreshTransport;
use runne_provider::CredentialVerificationCapability;
use runne_provider_quota::{
    QuotaEndpointScope, QuotaEvidenceSink, QuotaIdentity, QuotaParseError, QuotaProvider,
    QuotaRefreshStatus, QuotaRequestDescriptor, QuotaSnapshot, parse_kimi_usage,
    parse_minimax_quota, parse_qwen_token_plan, parse_zai_limits,
};
use runne_secure_store::ProviderCredentialVerificationMaterializer;
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

const MAX_BODY_BYTES: usize = 256 * 1024;

/// Explicit quota refresh bound to a remote verification capability and sink.
pub struct AuthorizedQuotaRefresher<T> {
    materializer: Arc<dyn ProviderCredentialVerificationMaterializer>,
    transport: Arc<T>,
    sink: Arc<dyn QuotaEvidenceSink>,
}

impl<T> AuthorizedQuotaRefresher<T>
where
    T: QuotaRefreshTransport + 'static,
{
    /// Builds a refresher; no network operation occurs until [`Self::refresh`].
    pub fn new(
        materializer: Arc<dyn ProviderCredentialVerificationMaterializer>,
        transport: Arc<T>,
        sink: Arc<dyn QuotaEvidenceSink>,
    ) -> Self {
        Self {
            materializer,
            transport,
            sink,
        }
    }

    /// Performs one separately authorized bounded quota read and records it.
    ///
    /// # Errors
    ///
    /// Returns a sanitized status when the lease, response, or provider schema
    /// cannot be verified. No request is made for an expired or mismatched lease.
    pub async fn refresh(
        &self,
        capability: &CredentialVerificationCapability,
        descriptor: &QuotaRequestDescriptor,
        model_name: Option<&str>,
        observed_at: u64,
    ) -> Result<QuotaSnapshot, QuotaRefreshStatus> {
        let provider = descriptor.provider();
        let provider_id = provider_id(&provider);
        if capability.lease().kind() != runne_provider::CredentialVerificationKind::Remote
            || capability.lease().provider().as_str() != provider_id
        {
            return Err(QuotaRefreshStatus::Unauthorized);
        }
        let lease_expiry = capability.lease().expires_at_high_water();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);
        if now_i64 >= lease_expiry {
            return Err(QuotaRefreshStatus::Unauthorized);
        }
        let lease_timeout = Duration::from_secs((lease_expiry - now_i64).cast_unsigned());
        let endpoint = descriptor
            .endpoint()
            .ok_or(QuotaRefreshStatus::ConsoleRequired)?;
        if descriptor.scope() != QuotaEndpointScope::ProviderApi || observed_at == 0 {
            return Err(QuotaRefreshStatus::UnknownSchema);
        }
        let identity = QuotaIdentity::new(
            provider_id,
            capability.lease().active_credential_version().version(),
        )
        .map_err(|_| QuotaRefreshStatus::UnknownSchema)?;
        if capability.binding_digest().as_bytes()
            != descriptor.binding_digest(identity.credential_version(), model_name)
        {
            return Err(QuotaRefreshStatus::Unauthorized);
        }
        let material = self
            .materializer
            .materialize_for_verification(capability)
            .map_err(|_| self.failure(&identity, QuotaRefreshStatus::Unauthorized))?;
        let token = material.with_bytes(|bytes| Zeroizing::new(bytes.to_vec()));
        let response = self
            .transport
            .get(
                endpoint.to_owned(),
                descriptor.auth_header(),
                token,
                lease_timeout,
            )
            .await
            .map_err(|_| self.failure(&identity, QuotaRefreshStatus::TransportUnavailable))?;
        if !(200..300).contains(&response.status)
            || !response
                .content_type
                .as_deref()
                .is_some_and(is_json_content_type)
            || response.body.len() > MAX_BODY_BYTES
        {
            let status = if response.status == 401 || response.status == 403 {
                QuotaRefreshStatus::Unauthorized
            } else {
                QuotaRefreshStatus::UnknownSchema
            };
            return Err(self.failure(&identity, status));
        }
        let snapshot = parse_snapshot(
            &provider,
            identity.clone(),
            observed_at,
            &response.body,
            model_name,
        )
        .map_err(|status| self.failure(&identity, status))?;
        self.sink
            .record_snapshot(snapshot.clone())
            .map_err(|_| QuotaRefreshStatus::TransportUnavailable)?;
        Ok(snapshot)
    }

    fn failure(&self, identity: &QuotaIdentity, status: QuotaRefreshStatus) -> QuotaRefreshStatus {
        let _ = self.sink.record_refresh_failure(identity, status);
        status
    }
}

fn parse_snapshot(
    provider: &QuotaProvider,
    identity: QuotaIdentity,
    observed_at: u64,
    body: &[u8],
    model_name: Option<&str>,
) -> Result<QuotaSnapshot, QuotaRefreshStatus> {
    let result = match provider {
        QuotaProvider::ZaiGlobal | QuotaProvider::ZaiChina => {
            parse_zai_limits(identity, observed_at, body)
        }
        QuotaProvider::KimiCoding => parse_kimi_usage(identity, observed_at, body),
        QuotaProvider::MiniMax | QuotaProvider::MiniMaxChina => parse_minimax_quota(
            identity,
            observed_at,
            body,
            model_name.ok_or(QuotaRefreshStatus::UnknownSchema)?,
        ),
        QuotaProvider::QwenTokenPlanIndividual => parse_qwen_token_plan(),
    };
    result.map_err(map_parse_error)
}

const fn map_parse_error(error: QuotaParseError) -> QuotaRefreshStatus {
    match error {
        QuotaParseError::ConsoleRequired => QuotaRefreshStatus::ConsoleRequired,
        QuotaParseError::BodyTooLarge
        | QuotaParseError::UnknownSchema
        | QuotaParseError::Invalid => QuotaRefreshStatus::UnknownSchema,
    }
}

fn is_json_content_type(value: &str) -> bool {
    let value = value.split(';').next().unwrap_or("").trim();
    value == "application/json" || value.ends_with("+json")
}

const fn provider_id(provider: &QuotaProvider) -> &'static str {
    match provider {
        QuotaProvider::ZaiGlobal => "zai",
        QuotaProvider::ZaiChina => "zai-coding-cn",
        QuotaProvider::QwenTokenPlanIndividual => "qwen-token-plan-individual",
        QuotaProvider::KimiCoding => "kimi-coding",
        QuotaProvider::MiniMax => "minimax",
        QuotaProvider::MiniMaxChina => "minimax-cn",
    }
}

#[cfg(test)]
#[path = "quota_refresh_tests.rs"]
mod quota_refresh_tests;
