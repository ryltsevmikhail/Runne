use reqwest::redirect::Policy;
use runne_provider::{CredentialDispatchCapability, NativeCredentialAuthority, ProviderFuture};
use runne_provider_deepseek::{
    DeepSeekCredentialError, DeepSeekCredentialMaterializer, DeepSeekTransportPolicy,
};
use runne_secure_store::{
    NativeProviderCredentialStore, NativeProviderCredentialVersionStore,
    ProviderCredentialAccessPolicy, SecureStoreError,
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
    store: Arc<dyn NativeProviderCredentialVersionStore>,
    access: ProviderCredentialAccessPolicy,
}

impl NativeCredential {
    pub(super) fn current_process() -> Result<Self, ()> {
        Err(())
    }

    pub(super) fn versioned(authority: NativeCredentialAuthority) -> Result<Self, ()> {
        let reader =
            std::fs::canonicalize(std::env::current_exe().map_err(|_| ())?).map_err(|_| ())?;
        let writer = reader.parent().ok_or(())?.join("runne");
        Ok(Self {
            store: Arc::new(NativeProviderCredentialStore::new_versioned(authority)),
            access: ProviderCredentialAccessPolicy::new(&writer, &reader).map_err(|_| ())?,
        })
    }
}

impl DeepSeekCredentialMaterializer for NativeCredential {
    fn materialize(
        &self,
        capability: &CredentialDispatchCapability,
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, DeepSeekCredentialError>> {
        let store = Arc::clone(&self.store);
        let access = self.access.clone();
        let capability = capability.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                store
                    .load_version(&capability, &access)
                    .map(|value| value.with_bytes(|bytes| Zeroizing::new(bytes.to_vec())))
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
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, DeepSeekCredentialError>> {
        Box::pin(async { Ok(Zeroizing::new(FIXTURE_CREDENTIAL.to_vec())) })
    }
}
