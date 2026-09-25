use reqwest::redirect::Policy;
use runne_provider::{
    CredentialDispatchCapability, CredentialFence, CredentialLifecycleRevision, ProviderFuture,
};
use runne_provider_deepseek::{
    DeepSeekCredentialError, DeepSeekCredentialMaterializer, DeepSeekTransportPolicy,
};
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead, SecureStoreError,
};
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

pub(super) fn production_client(policy: &DeepSeekTransportPolicy) -> Result<reqwest::Client, ()> {
    client_builder(policy).build().map_err(|_| ())
}

/// Builds a fixture-only loopback route using the production client settings.
#[doc(hidden)]
pub fn loopback_fixture_client(
    policy: &DeepSeekTransportPolicy,
    address: SocketAddr,
    certificate_der: &[u8],
) -> Result<reqwest::Client, crate::DeepSeekEffectError> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(crate::DeepSeekEffectError);
    }
    let certificate =
        reqwest::Certificate::from_der(certificate_der).map_err(|_| crate::DeepSeekEffectError)?;
    client_builder(policy)
        .resolve("api.deepseek.com", address)
        .add_root_certificate(certificate)
        .build()
        .map_err(|_| crate::DeepSeekEffectError)
}

fn client_builder(policy: &DeepSeekTransportPolicy) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(policy.connect_timeout())
}

pub(super) struct NativeCredential {
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
}

impl NativeCredential {
    pub(super) fn current_process() -> Result<Self, ()> {
        Err(())
    }

    pub(super) fn from_materializer(
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    ) -> Self {
        Self { materializer }
    }
}

impl DeepSeekCredentialMaterializer for NativeCredential {
    fn materialize(
        &self,
        capability: &CredentialDispatchCapability,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        effect_receipt_digest: [u8; 32],
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, DeepSeekCredentialError>> {
        let materializer = Arc::clone(&self.materializer);
        let capability = capability.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let read = ProviderCredentialDispatchRead::new(
                    &capability,
                    lifecycle,
                    fence,
                    effect_receipt_digest,
                )
                .map_err(|_| DeepSeekCredentialError::AccessDenied)?;
                materializer
                    .materialize_active(read)
                    .map(|material| material.into_zeroizing().1)
                    .map_err(|error| match error {
                        SecureStoreError::ProviderCredentialNotFound => {
                            DeepSeekCredentialError::Missing
                        }
                        _ => DeepSeekCredentialError::AccessDenied,
                    })
            })
            .await
            .map_err(|_| DeepSeekCredentialError::AccessDenied)?
        })
    }
}

pub(super) struct FixtureCredential;

const FIXTURE_CREDENTIAL: &[u8] = b"fixture-credential";

/// Opaque fixture-only authorization matcher. Credential bytes never leave this crate.
#[doc(hidden)]
pub struct FixtureRequestAuthenticator {
    expected: Zeroizing<Vec<u8>>,
}

impl FixtureCredential {
    pub(super) fn new() -> Self {
        Self
    }

    pub(super) fn request_authenticator(&self) -> FixtureRequestAuthenticator {
        FixtureRequestAuthenticator {
            expected: Zeroizing::new([b"Bearer ".as_slice(), FIXTURE_CREDENTIAL].concat()),
        }
    }
}

impl FixtureRequestAuthenticator {
    /// Compares an authorization field without exposing or logging its expected bytes.
    #[doc(hidden)]
    pub fn matches(&self, candidate: &[u8]) -> bool {
        candidate.len() == self.expected.len()
            && bool::from(candidate.ct_eq(self.expected.as_slice()))
    }
}

impl DeepSeekCredentialMaterializer for FixtureCredential {
    fn materialize(
        &self,
        _capability: &CredentialDispatchCapability,
        _lifecycle: CredentialLifecycleRevision,
        _fence: CredentialFence,
        _effect_receipt_digest: [u8; 32],
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, DeepSeekCredentialError>> {
        Box::pin(async { Ok(Zeroizing::new(FIXTURE_CREDENTIAL.to_vec())) })
    }

    fn materialize_legacy_fixture(
        &self,
        _capability: &CredentialDispatchCapability,
        _effect_receipt_digest: [u8; 32],
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, DeepSeekCredentialError>> {
        Box::pin(async { Ok(Zeroizing::new(FIXTURE_CREDENTIAL.to_vec())) })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use runne_provider::{
        CredentialAuthorityPair, CredentialLease, CredentialVersionRef, ProviderId,
    };
    use runne_secure_store::{
        ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
        ProviderCredentialMaterial,
    };

    use super::*;

    struct Materializer {
        expected: CredentialVersionRef,
        calls: AtomicUsize,
        result: Result<Vec<u8>, ()>,
    }

    impl ProviderCredentialDispatchMaterializer for Materializer {
        fn materialize_active(
            &self,
            read: ProviderCredentialDispatchRead<'_>,
        ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
            assert_eq!(read.capability().version_ref(), &self.expected);
            assert_eq!(read.lifecycle().get(), 2);
            assert_eq!(read.fence().get(), 3);
            assert_eq!(read.effect_receipt_digest(), [4; 32]);
            self.calls.fetch_add(1, Ordering::SeqCst);
            let bytes = self
                .result
                .clone()
                .map_err(|_| SecureStoreError::ProviderCredentialNotFound)?;
            ProviderCredentialMaterial::new(bytes)
        }
    }

    fn capability() -> CredentialDispatchCapability {
        let (lifecycle, _) = CredentialAuthorityPair::new().split();
        let reference = CredentialVersionRef::new(ProviderId::new("deepseek").unwrap(), 7).unwrap();
        lifecycle.issue_dispatch(CredentialLease::new(reference, [1; 16], 1, 1).unwrap())
    }

    #[tokio::test]
    async fn native_credential_materializes_active_capability_into_zeroizing_bytes() {
        let capability = capability();
        let materializer = Arc::new(Materializer {
            expected: capability.version_ref().clone(),
            calls: AtomicUsize::new(0),
            result: Ok(b"narrow-material".to_vec()),
        });
        let dispatch: Arc<dyn ProviderCredentialDispatchMaterializer> = materializer.clone();
        let credential = NativeCredential::from_materializer(dispatch);

        let material = credential
            .materialize(
                &capability,
                CredentialLifecycleRevision::new(2).unwrap(),
                CredentialFence::new(3).unwrap(),
                [4; 32],
            )
            .await
            .unwrap();

        assert_eq!(material.as_slice(), b"narrow-material");
        assert_eq!(materializer.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn native_credential_maps_missing_material_to_missing() {
        let capability = capability();
        let credential = NativeCredential::from_materializer(Arc::new(Materializer {
            expected: capability.version_ref().clone(),
            calls: AtomicUsize::new(0),
            result: Err(()),
        }));

        assert!(matches!(
            credential
                .materialize(
                    &capability,
                    CredentialLifecycleRevision::new(2).unwrap(),
                    CredentialFence::new(3).unwrap(),
                    [4; 32],
                )
                .await,
            Err(DeepSeekCredentialError::Missing)
        ));
    }

    #[tokio::test]
    async fn native_credential_rejects_the_legacy_fixture_fallback() {
        let capability = capability();
        let materializer = Arc::new(Materializer {
            expected: capability.version_ref().clone(),
            calls: AtomicUsize::new(0),
            result: Ok(b"must-not-load".to_vec()),
        });
        let credential = NativeCredential::from_materializer(materializer.clone());

        assert_eq!(
            credential
                .materialize_legacy_fixture(&capability, [5; 32])
                .await,
            Err(DeepSeekCredentialError::AccessDenied)
        );
        assert_eq!(materializer.calls.load(Ordering::SeqCst), 0);
    }
}
