use std::sync::atomic::{AtomicUsize, Ordering};

use gocode_api::ProviderActivationBindingV1;
use gocode_application::provider::ProviderJournalKeyBinding;
use gocode_daemon::canonical_provider::{
    ProviderReadinessError, ProviderReadinessEvidence, compose_selected_provider,
};
use gocode_daemon::provider_activation::ProviderActivation;
use gocode_secure_store::{ProviderCredentialStatus, ProviderJournalKeyStatus};

#[tokio::test]
async fn deterministic_activation_performs_zero_credential_key_or_network_composition_probes() {
    let probes = AtomicUsize::new(0);
    let result = compose_selected_provider(&ProviderActivation::deterministic_v1(), || async {
        probes.fetch_add(1, Ordering::SeqCst);
        Ok::<_, gocode_daemon::error::DaemonError>(())
    })
    .await
    .unwrap();

    assert_eq!(result, None);
    assert_eq!(probes.load(Ordering::SeqCst), 0);
}

fn readiness() -> ProviderReadinessEvidence {
    let binding = ProviderActivationBindingV1::openai_responses_text_v1();
    ProviderReadinessEvidence {
        profile_id: binding.profile_id().to_owned(),
        profile_digest: *binding.profile_digest(),
        activation_profile_id: binding.profile_id().to_owned(),
        activation_profile_digest: *binding.profile_digest(),
        retained_key_backend: true,
        credential_status: ProviderCredentialStatus::Configured,
        journal_binding: Some(ProviderJournalKeyBinding::new([1; 16], 1, [2; 16], 3).unwrap()),
        journal_key_status: ProviderJournalKeyStatus::Available,
        runtime_authority_id: [2; 16],
        database_generation: 3,
    }
}

#[test]
fn every_provider_pre_readiness_gate_is_typed_and_fail_closed() {
    assert_eq!(readiness().validate(), Ok(()));

    let mut profile = readiness();
    profile.activation_profile_digest = [9; 32];
    assert_eq!(
        profile.validate(),
        Err(ProviderReadinessError::ProfileBinding)
    );

    let mut backend = readiness();
    backend.retained_key_backend = false;
    assert_eq!(
        backend.validate(),
        Err(ProviderReadinessError::SecureStoreBackend)
    );

    let mut credential = readiness();
    credential.credential_status = ProviderCredentialStatus::Missing;
    assert_eq!(
        credential.validate(),
        Err(ProviderReadinessError::Credential)
    );

    let mut unsupported_credential = readiness();
    unsupported_credential.credential_status = ProviderCredentialStatus::Unsupported;
    assert_eq!(
        unsupported_credential.validate(),
        Err(ProviderReadinessError::Credential)
    );

    let mut key = readiness();
    key.journal_key_status = ProviderJournalKeyStatus::Missing;
    assert_eq!(key.validate(), Err(ProviderReadinessError::JournalKey));

    let mut binding = readiness();
    binding.runtime_authority_id = [8; 16];
    assert_eq!(binding.validate(), Err(ProviderReadinessError::JournalKey));
}

#[tokio::test]
async fn exact_openai_activation_requires_the_concrete_pre_readiness_composition_probe() {
    let probes = AtomicUsize::new(0);
    let activation =
        ProviderActivation::from_binding(ProviderActivationBindingV1::openai_responses_text_v1());
    let result = compose_selected_provider(&activation, || async {
        probes.fetch_add(1, Ordering::SeqCst);
        Ok::<_, gocode_daemon::error::DaemonError>(17_u8)
    })
    .await
    .unwrap();

    assert_eq!(result, Some(17));
    assert_eq!(probes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exact_deepseek_activation_requires_the_concrete_pre_readiness_composition_probe() {
    let probes = AtomicUsize::new(0);
    let activation =
        ProviderActivation::from_binding(ProviderActivationBindingV1::deepseek_responses_text_v1());
    let result = compose_selected_provider(&activation, || async {
        probes.fetch_add(1, Ordering::SeqCst);
        Ok::<_, gocode_daemon::error::DaemonError>(19_u8)
    })
    .await
    .unwrap();

    assert_eq!(result, Some(19));
    assert_eq!(probes.load(Ordering::SeqCst), 1);
}
