use std::any::Any;
use std::sync::Arc;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use runne_provider::{DispatchError, DispatchRequest, ProviderStreamId};
use runne_provider_deepseek::{
    DeepSeekCredentialError, DeepSeekCredentialMaterializer, DeepSeekTransportPolicy,
    DeepSeekTransportResponse,
};
use runne_secure_store::ProviderCredentialDispatchMaterializer;
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectStartReceipt, ProviderReadyEffect,
};
use tokio::time::timeout_at;

use crate::bounds::{
    ResponseContract, accepted_response_contract, append_bounded, bearer_header, record_chunk,
    wait_for_chunk,
};
use crate::diagnostics::{DeepSeekEffectDiagnostic as Diagnostic, DeepSeekHttpStatusClass};
use crate::{DeepSeekEffect, DeepSeekEffectError, REQUEST_ID, Sender, client, profile};

pub(super) struct AuthorizedReady {
    pub(super) request: DispatchRequest,
    pub(super) credential: CredentialDispatchBinding,
}

impl ProviderReadyEffect for AuthorizedReady {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

impl dyn DeepSeekEffect {
    /// Creates the production effect with the runtime-owned credential materializer.
    pub fn production(
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    ) -> Result<Arc<dyn DeepSeekEffect>, DeepSeekEffectError> {
        Self::production_inner(materializer, None)
    }

    #[cfg(feature = "linux-native-enrollment-qualification")]
    #[doc(hidden)]
    pub fn production_with_observer(
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        observer: Arc<dyn crate::diagnostics::DeepSeekEffectObserver>,
    ) -> Result<Arc<dyn DeepSeekEffect>, DeepSeekEffectError> {
        Self::production_inner(materializer, Some(observer))
    }

    fn production_inner(
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        observer: Option<Arc<dyn crate::diagnostics::DeepSeekEffectObserver>>,
    ) -> Result<Arc<dyn DeepSeekEffect>, DeepSeekEffectError> {
        let profile = profile().map_err(|_| DeepSeekEffectError)?;
        let policy =
            DeepSeekTransportPolicy::for_profile(&profile).map_err(|_| DeepSeekEffectError)?;
        let credential = client::NativeCredential::from_materializer(materializer);
        Ok(Arc::new(
            Sender::new_with_observer(
                profile,
                credential,
                client::production_client(&policy).map_err(|_| DeepSeekEffectError)?,
                observer,
            )
            .map_err(|_| DeepSeekEffectError)?,
        ))
    }
}

impl<C: DeepSeekCredentialMaterializer> Sender<C> {
    pub(super) async fn send_authorized(
        &self,
        ready: AuthorizedReady,
        receipt: ProviderEffectStartReceipt,
    ) -> Result<ProviderStreamId, DispatchError> {
        if !receipt.matches_claim(ready.request.claim())
            || !receipt.matches_credential(&ready.credential)
            || ready.request.claim().profile_digest != self.profile.profile_digest()
        {
            self.observe(Diagnostic::ReceiptRejected);
            return Err(DispatchError::MaybeDispatched);
        }
        let request_id = match HeaderValue::from_str(ready.request.provider_idempotency_key()) {
            Ok(value) => value,
            Err(_) => {
                self.observe(Diagnostic::RequestIdRejected);
                return Err(DispatchError::MaybeDispatched);
            }
        };
        let receipt_digest = receipt.credential_read_receipt_digest();
        self.observe(Diagnostic::MaterializationStarted);
        let material = match ready.credential.point_of_use_revisions() {
            Ok((lifecycle, fence)) => {
                self.credential
                    .materialize(
                        ready.credential.native_capability(),
                        lifecycle,
                        fence,
                        receipt_digest,
                    )
                    .await
            }
            Err(_) => {
                self.credential
                    .materialize_legacy_fixture(
                        ready.credential.native_capability(),
                        receipt_digest,
                    )
                    .await
            }
        };
        let material = match material {
            Ok(material) => {
                self.observe(Diagnostic::Materialized);
                material
            }
            Err(DeepSeekCredentialError::Missing) => {
                self.observe(Diagnostic::MaterializationMissing);
                return Err(super::map_credential(DeepSeekCredentialError::Missing));
            }
            Err(DeepSeekCredentialError::AccessDenied) => {
                self.observe(Diagnostic::MaterializationAccessDenied);
                return Err(super::map_credential(DeepSeekCredentialError::AccessDenied));
            }
        };
        let credential = match bearer_header(&material) {
            Ok(credential) => credential,
            Err(error) => {
                self.observe(Diagnostic::AuthorizationHeaderRejected);
                return Err(error);
            }
        };
        let url = format!("{}{}", self.policy.origin(), self.policy.path());
        let effect = async {
            self.observe(Diagnostic::RequestSendStarted);
            let response = match self
                .client
                .post(url)
                .header(REQUEST_ID, request_id)
                .header(AUTHORIZATION, credential)
                .header(CONTENT_TYPE, "application/json")
                .body(ready.request.prepared().rendered_bytes().to_vec())
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => {
                    self.observe(Diagnostic::RequestSendFailed);
                    return Err(DispatchError::MaybeDispatched);
                }
            };
            let status = response.status().as_u16();
            self.observe(Diagnostic::ResponseStatus(
                DeepSeekHttpStatusClass::from_status(status),
            ));
            let contract = match accepted_response_contract(
                response.url().as_str(),
                status,
                response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
            ) {
                Some(ResponseContract::Sse) => {
                    self.observe(Diagnostic::ResponseContractSse);
                    ResponseContract::Sse
                }
                Some(ResponseContract::JsonRejection(status)) => {
                    self.observe(Diagnostic::ResponseContractJsonRejection);
                    ResponseContract::JsonRejection(status)
                }
                None => {
                    self.observe(Diagnostic::ResponseContractRejected);
                    return Err(DispatchError::MaybeDispatched);
                }
            };
            let maximum = match contract {
                ResponseContract::Sse => self.policy.max_decoded_bytes(),
                ResponseContract::JsonRejection(_) => self.policy.max_frame_bytes(),
            };
            let mut response = response;
            let mut body = Vec::new();
            let mut chunks = 0;
            loop {
                let chunk = match wait_for_chunk(self.policy.idle_timeout(), response.chunk()).await
                {
                    Err(_) => {
                        self.observe(Diagnostic::BodyIdleTimeout);
                        return Err(DispatchError::MaybeDispatched);
                    }
                    Ok(Err(_)) => {
                        self.observe(Diagnostic::BodyReadFailed);
                        return Err(DispatchError::MaybeDispatched);
                    }
                    Ok(Ok(chunk)) => chunk,
                };
                let Some(chunk) = chunk else { break };
                if record_chunk(&mut chunks, self.policy.max_transport_chunks()).is_err() {
                    self.observe(Diagnostic::BodyChunkLimitExceeded);
                    return Err(DispatchError::MaybeDispatched);
                }
                if append_bounded(&mut body, &chunk, maximum).is_err() {
                    self.observe(Diagnostic::BodyByteLimitExceeded);
                    return Err(DispatchError::MaybeDispatched);
                }
            }
            if body.is_empty() {
                self.observe(Diagnostic::BodyEmpty);
                return Err(DispatchError::MaybeDispatched);
            }
            self.observe(Diagnostic::BodyComplete);
            let response = match contract {
                ResponseContract::Sse => DeepSeekTransportResponse::sse(vec![body]),
                ResponseContract::JsonRejection(status) => {
                    DeepSeekTransportResponse::json_rejection(status, body)
                }
            };
            let response = match response {
                Ok(response) => response,
                Err(_) => {
                    self.observe(Diagnostic::ResponseConstructionFailed);
                    return Err(DispatchError::MaybeDispatched);
                }
            };
            self.store_response(ready.request.attempt_id(), response)
        };
        match timeout_at(receipt.deadline().into(), effect).await {
            Ok(result) => result,
            Err(_) => {
                self.observe(Diagnostic::DeadlineExpired);
                Err(DispatchError::MaybeDispatched)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use runne_secure_store::{
        ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
        ProviderCredentialMaterial, SecureStoreError,
    };

    use super::*;

    struct DenyingMaterializer;

    impl ProviderCredentialDispatchMaterializer for DenyingMaterializer {
        fn materialize_active(
            &self,
            _: ProviderCredentialDispatchRead<'_>,
        ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
            Err(SecureStoreError::CredentialAccessDenied)
        }
    }

    #[test]
    fn production_accepts_narrow_dispatch_materializer() {
        let materializer: Arc<dyn ProviderCredentialDispatchMaterializer> =
            Arc::new(DenyingMaterializer);

        assert!(<dyn DeepSeekEffect>::production(materializer).is_ok());
    }
}
