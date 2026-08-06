use gocode_provider::ProviderFuture;
use gocode_provider_openai::{
    OpenAiCredentialError, OpenAiCredentialMaterializer, OpenAiTransportPolicy,
};
use gocode_secure_store::{
    NativeProviderCredentialStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialStore, SecureStoreError,
};
use reqwest::redirect::Policy;
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

pub(super) fn production_client(policy: &OpenAiTransportPolicy) -> Result<reqwest::Client, ()> {
    client_builder(policy).build().map_err(|_| ())
}

/// Builds a fixture-only loopback route using the production client settings.
#[doc(hidden)]
pub fn loopback_fixture_client(
    policy: &OpenAiTransportPolicy,
    address: SocketAddr,
    certificate_der: &[u8],
) -> Result<reqwest::Client, crate::OpenAiEffectError> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(crate::OpenAiEffectError);
    }
    let certificate =
        reqwest::Certificate::from_der(certificate_der).map_err(|_| crate::OpenAiEffectError)?;
    client_builder(policy)
        .resolve("api.openai.com", address)
        .add_root_certificate(certificate)
        .build()
        .map_err(|_| crate::OpenAiEffectError)
}

fn client_builder(policy: &OpenAiTransportPolicy) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(policy.connect_timeout())
}

pub(super) struct NativeCredential {
    store: Arc<dyn ProviderCredentialStore>,
    access: ProviderCredentialAccessPolicy,
}

impl NativeCredential {
    pub(super) fn current_process() -> Result<Self, ()> {
        let reader =
            std::fs::canonicalize(std::env::current_exe().map_err(|_| ())?).map_err(|_| ())?;
        let writer = reader.parent().ok_or(())?.join("gocode");
        Ok(Self {
            store: Arc::new(NativeProviderCredentialStore::new()),
            access: ProviderCredentialAccessPolicy::new(&writer, &reader).map_err(|_| ())?,
        })
    }
}

impl OpenAiCredentialMaterializer for NativeCredential {
    fn materialize(&self) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, OpenAiCredentialError>> {
        let store = Arc::clone(&self.store);
        let access = self.access.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                store
                    .load_provider_credential(ProviderCredentialId::OpenAi, &access)
                    .map(|value| value.with_bytes(|bytes| Zeroizing::new(bytes.to_vec())))
                    .map_err(|error| match error {
                        SecureStoreError::ProviderCredentialNotFound => {
                            OpenAiCredentialError::Missing
                        }
                        _ => OpenAiCredentialError::AccessDenied,
                    })
            })
            .await
            .map_err(|_| OpenAiCredentialError::AccessDenied)?
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

impl OpenAiCredentialMaterializer for FixtureCredential {
    fn materialize(&self) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, OpenAiCredentialError>> {
        Box::pin(async { Ok(Zeroizing::new(FIXTURE_CREDENTIAL.to_vec())) })
    }
}
