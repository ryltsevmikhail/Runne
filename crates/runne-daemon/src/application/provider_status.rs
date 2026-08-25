use crate::provider_activation::ProviderActivation;
use runne_api::{
    ProviderActivationBindingV1, ProviderActivationModeV1, ProviderActivationReadinessV1,
    ProviderReadinessStatusV1, ProviderStatusSnapshotV1,
};

pub(super) fn provider_statuses(
    activation: &ProviderActivation,
    readiness: ProviderActivationReadinessV1,
) -> Vec<ProviderStatusSnapshotV1> {
    let known = [
        (
            "deterministic",
            ProviderActivationBindingV1::deterministic_v1(),
        ),
        (
            "openai",
            ProviderActivationBindingV1::openai_responses_text_v1(),
        ),
        (
            "deepseek",
            ProviderActivationBindingV1::deepseek_responses_text_v1(),
        ),
    ];
    known
        .into_iter()
        .map(|(provider_id, binding)| {
            let selected = binding == *activation.binding();
            let readiness = if selected {
                selected_readiness(binding.mode(), readiness)
            } else {
                ProviderReadinessStatusV1::NotSelected
            };
            ProviderStatusSnapshotV1::new(
                provider_id,
                binding.mode().as_str(),
                binding.profile_id(),
                *binding.profile_digest(),
                readiness,
                selected,
            )
            .expect("released provider activation metadata is valid")
        })
        .collect()
}

fn selected_readiness(
    mode: ProviderActivationModeV1,
    readiness: ProviderActivationReadinessV1,
) -> ProviderReadinessStatusV1 {
    if mode == ProviderActivationModeV1::DeterministicV1 {
        return ProviderReadinessStatusV1::Ready;
    }
    match readiness {
        ProviderActivationReadinessV1::Ready => ProviderReadinessStatusV1::Ready,
        ProviderActivationReadinessV1::CredentialMissing => {
            ProviderReadinessStatusV1::CredentialMissing
        }
        ProviderActivationReadinessV1::CredentialAccessDenied => {
            ProviderReadinessStatusV1::CredentialAccessDenied
        }
        ProviderActivationReadinessV1::CredentialIdentityMismatch => {
            ProviderReadinessStatusV1::CredentialIdentityMismatch
        }
        ProviderActivationReadinessV1::SecureStoreUnavailable => {
            ProviderReadinessStatusV1::SecureStoreUnavailable
        }
    }
}
