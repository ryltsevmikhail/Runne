use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use runne_provider::ProviderId;
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial, SecureStoreError,
};
use runne_store::provider::ProviderFinalSendAuthority;

pub(in crate::canonical_provider::composition::tests) struct FinalSendBarrier {
    pub(in crate::canonical_provider::composition::tests) entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
    pub(in crate::canonical_provider::composition::tests) transport_entries: AtomicUsize,
    pub(in crate::canonical_provider::composition::tests) posts: AtomicUsize,
}

impl FinalSendBarrier {
    pub(in crate::canonical_provider::composition::tests) fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
            transport_entries: AtomicUsize::new(0),
            posts: AtomicUsize::new(0),
        })
    }

    pub(in crate::canonical_provider::composition::tests) async fn wait_before_consume(
        &self,
        authority: ProviderFinalSendAuthority,
    ) -> Result<(), ()> {
        self.transport_entries.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        let permit = self.release.acquire().await.map_err(|_| ())?;
        permit.forget();
        authority.consume().map_err(|_| ())?;
        self.posts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    pub(in crate::canonical_provider::composition::tests) fn release(&self) {
        self.release.add_permits(1);
    }
}

pub(in crate::canonical_provider::composition::tests) struct OnlineFixtureMaterializer {
    provider: ProviderId,
    pub(in crate::canonical_provider::composition::tests) calls: AtomicUsize,
}

impl OnlineFixtureMaterializer {
    pub(in crate::canonical_provider::composition::tests) fn new(provider: &str) -> Arc<Self> {
        Arc::new(Self {
            provider: ProviderId::new(provider).unwrap(),
            calls: AtomicUsize::new(0),
        })
    }
}

impl ProviderCredentialDispatchMaterializer for OnlineFixtureMaterializer {
    fn materialize_active(
        &self,
        read: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        assert_eq!(read.capability().version_ref().provider(), &self.provider);
        assert_ne!(read.effect_receipt_digest(), [0; 32]);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let version = read.capability().version_ref().version();
        let bytes = if self.provider.as_str() == "openai-codex" {
            format!(
                "{{\"schema\":\"runne.oauth-credential/v1\",\"provider\":\"openai-codex\",\"credential_version\":{version},\"access_token\":\"fixture-access\",\"refresh_token\":\"fixture-refresh\",\"account_id\":\"fixture-account\",\"expires_at_unix_seconds\":4102444800}}"
            )
            .into_bytes()
        } else {
            b"test-only online credential material".to_vec()
        };
        ProviderCredentialMaterial::new(bytes)
    }
}
