use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial, SecureStoreError,
};

pub(super) struct MaterializationBarrier {
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    release: Condvar,
}

impl MaterializationBarrier {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Notify::new(),
            released: Mutex::new(false),
            release: Condvar::new(),
        })
    }

    pub(super) async fn wait_until_entered(&self) {
        self.entered.notified().await;
    }

    pub(super) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_all();
    }

    fn pause(&self) {
        self.entered.notify_one();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.release.wait(released).unwrap();
        }
    }
}

pub(super) struct PausedMaterializer {
    provider: String,
    barrier: Arc<MaterializationBarrier>,
    calls: AtomicUsize,
}

impl PausedMaterializer {
    pub(super) fn new(provider: &str, barrier: Arc<MaterializationBarrier>) -> Arc<Self> {
        Arc::new(Self {
            provider: provider.to_owned(),
            barrier,
            calls: AtomicUsize::new(0),
        })
    }

    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ProviderCredentialDispatchMaterializer for PausedMaterializer {
    fn materialize_active(
        &self,
        read: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        assert_eq!(
            read.capability().version_ref().provider().as_str(),
            self.provider
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.barrier.pause();
        ProviderCredentialMaterial::new(b"test-only online fixture credential".to_vec())
    }
}
