use super::*;
use runne_provider::{
    BeginCredentialVerification, CredentialBindingDigest, CredentialEnrollmentAuthorityPair,
    CredentialFence, CredentialLifecycleRevision, CredentialOperationId,
    CredentialReadinessRevision, CredentialVerifierRevision, CredentialVersionRef, ProviderId,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct RecordingNative {
    expected_provider: ProviderId,
    expected_version: u64,
    calls: Arc<AtomicUsize>,
}

impl VerificationNativeMaterializer for RecordingNative {
    fn materialize_for_verification(
        &self,
        capability: &CredentialVerificationCapability,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if capability.lease().provider() != &self.expected_provider
            || capability.lease().active_credential_version().version() != self.expected_version
        {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        ProviderCredentialMaterial::new(b"quota-fixture".to_vec())
    }
}

#[test]
fn adapter_rejects_local_capability_before_native_access() {
    let native = RecordingNative {
        expected_provider: ProviderId::new("kimi-coding").unwrap(),
        expected_version: 1,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let calls = Arc::clone(&native.calls);
    let adapter = VerificationMaterializerAdapter::new(native, test_access());
    let capability = capability("kimi-coding", 1, CredentialVerificationKind::Local);
    assert_eq!(
        adapter
            .materialize_for_verification(&capability)
            .unwrap_err(),
        SecureStoreError::CredentialAccessDenied
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn adapter_delegates_only_exact_provider_and_version() {
    let native = RecordingNative {
        expected_provider: ProviderId::new("kimi-coding").unwrap(),
        expected_version: 7,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let adapter = VerificationMaterializerAdapter::new(native, test_access());
    let valid = capability("kimi-coding", 7, CredentialVerificationKind::Remote);
    assert!(adapter.materialize_for_verification(&valid).is_ok());
    let wrong_provider = capability("openai", 7, CredentialVerificationKind::Remote);
    assert_eq!(
        adapter
            .materialize_for_verification(&wrong_provider)
            .unwrap_err(),
        SecureStoreError::CredentialAccessDenied
    );
}

fn capability(
    provider_name: &str,
    version: u64,
    kind: CredentialVerificationKind,
) -> CredentialVerificationCapability {
    let provider = ProviderId::new(provider_name).unwrap();
    let begin = BeginCredentialVerification::new(
        CredentialOperationId::from_bytes([u8::try_from(version).unwrap(); 16]).unwrap(),
        None,
        provider.clone(),
        kind,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialReadinessRevision::new(1).unwrap(),
        CredentialBindingDigest::from_measured([1; 32]).unwrap(),
        CredentialBindingDigest::from_measured([2; 32]).unwrap(),
        CredentialVerifierRevision::new(1).unwrap(),
        1,
        i64::MAX,
    )
    .unwrap();
    let (store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let lease = store.issue_credential_verification_lease(
        begin,
        CredentialVersionRef::new(provider, version).unwrap(),
    );
    measurements
        .issue_credential_verification_capability(
            lease,
            CredentialBindingDigest::from_measured([3; 32]).unwrap(),
        )
        .unwrap()
}

fn test_access() -> ProviderCredentialAccessPolicy {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("runne");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    ProviderCredentialAccessPolicy::new(&executable, &executable).unwrap()
}
