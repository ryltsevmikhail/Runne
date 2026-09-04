use runne_provider::*;
use runne_secure_store::SecureStoreError;
use runne_secure_store::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct MetadataReader {
    calls: Arc<AtomicUsize>,
    present: bool,
}

#[tokio::test]
async fn expired_registration_does_not_invoke_legacy_metadata_reader() {
    let (authority, _) = CredentialEnrollmentAuthorityPair::new().split();
    let calls = Arc::new(AtomicUsize::new(0));
    let gateway =
        super::CredentialServiceRuntimeGateway::new(authority, tokio::runtime::Handle::current())
            .with_legacy_readback(Arc::new(MetadataReader {
                calls: calls.clone(),
                present: false,
            }));
    gateway
        .install(super::session(
            &super::binding(2, super::uuid(1), 11, 13, 1, [4; 32]),
            7,
        ))
        .unwrap();
    assert!(gateway.readback_exact_absence(input()).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
impl ProviderCredentialReadback for MetadataReader {
    fn readback_exact_version(
        &self,
        _: ExactVersionReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        panic!("legacy port must not receive version reads")
    }
    fn readback_exact_absence(
        &self,
        input: ExactAbsenceReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        assert!(matches!(
            input.command().target(),
            CredentialBrokerTarget::ExactLegacySource(_)
        ));
        self.calls.fetch_add(1, Ordering::SeqCst);
        input.observe_service_presence(self.present)
    }
}

fn input() -> ExactAbsenceReadback {
    let provider = ProviderId::new("openai").unwrap();
    let binding = CredentialLegacyCleanupBinding::from_parts(
        CredentialOperationId::from_bytes([1; 16]).unwrap(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialVersionRef::new(provider.clone(), 1).unwrap(),
        CredentialBindingDigest::from_measured([7; 32]).unwrap(),
    );
    ExactAbsenceReadback::new(
        CredentialBrokerCommand::new(
            CredentialOperationId::from_bytes([2; 16]).unwrap(),
            CredentialTicketAttempt::new(1).unwrap(),
            provider,
            CredentialOperationAction::LegacySourceCleanup,
            CredentialBrokerTarget::ExactLegacySource(binding),
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialFence::new(2).unwrap(),
            None,
        )
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn legacy_metadata_read_requires_registration_and_preserves_presence_conflict() {
    for present in [false, true] {
        let (authority, _) = CredentialEnrollmentAuthorityPair::new().split();
        let calls = Arc::new(AtomicUsize::new(0));
        let gateway = super::CredentialServiceRuntimeGateway::new(
            authority,
            tokio::runtime::Handle::current(),
        )
        .with_legacy_readback(Arc::new(MetadataReader {
            calls: calls.clone(),
            present,
        }));
        assert!(matches!(
            gateway.readback_exact_absence(input()),
            Err(SecureStoreError::Unavailable)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        gateway.install(super::session(&live_binding(), 7)).unwrap();
        let result = gateway.readback_exact_absence(input());
        if present {
            assert!(matches!(
                result,
                Err(SecureStoreError::ProviderCredentialOperationFailed)
            ));
        } else {
            assert!(!result.unwrap().present());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

fn live_binding() -> runne_api::CredentialServiceRegistrationBinding {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    runne_api::CredentialServiceRegistrationBinding::new(
        [2; 16],
        super::uuid(1),
        11,
        11,
        13,
        14,
        [3; 32],
        [4; 32],
        [3; 16],
        1,
        u64::try_from(now).unwrap() + 60_000,
    )
    .unwrap()
}
