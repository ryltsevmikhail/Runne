use super::*;
use crate::application::provider_credential_enrollment::linux_preadmission::DaemonLinuxPreadmission;
use runne_api::provider_credential_enrollment::linux_activation_policy::{
    LinuxEnrollmentActivationRecord, LinuxInstallationFacts,
};

fn record() -> LinuxEnrollmentActivationRecord {
    LinuxEnrollmentActivationRecord {
        provider_scope: runne_api::provider_credential_enrollment::linux_activation_policy::LinuxEnrollmentScope::LegacyDeepSeek,
        runtime_root_digest: [1; 32],
        desktop_image_digest: [2; 32],
        writer_image_digest: [3; 32],
        daemon_image_digest: [4; 32],
        runtime_authority_id: [5; 16],
        machine_id_digest: [6; 32],
        approved_at_unix_millis: 1_700_000_000_000,
    }
}

fn facts() -> LinuxInstallationFacts {
    LinuxInstallationFacts {
        runtime_root_digest: [1; 32],
        desktop_image_digest: [2; 32],
        writer_image_digest: [3; 32],
        daemon_image_digest: [4; 32],
        runtime_authority_id: [5; 16],
        machine_id_digest: [6; 32],
    }
}

fn gated_registry(gate: DaemonLinuxPreadmission) -> PendingCredentialAdmissions {
    let (request, admission) = verified_frames();
    let _ = (request, admission);
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    PendingCredentialAdmissions::new(issuer).with_linux_preadmission(gate)
}

#[test]
fn approved_fixture_admits_deepseek_through_registry_entry() {
    let registry = gated_registry(DaemonLinuxPreadmission::from_parts(Some(record()), facts()));
    let (request, admission) = verified_frames();
    registry
        .register(
            request,
            admission,
            context(),
            100_000,
            ProviderCredentialProviderV2::DeepSeek,
        )
        .expect("approved installation admits DeepSeek before broker transfer");
}

#[test]
fn wrong_provider_denies_before_admission() {
    let registry = gated_registry(DaemonLinuxPreadmission::from_parts(Some(record()), facts()));
    let (request, admission) = verified_frames();
    let error = registry
        .register(
            request,
            admission,
            context(),
            100_000,
            ProviderCredentialProviderV2::OpenAi,
        )
        .expect_err("non-allowlisted provider denies");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::Unsupported
    ));
}

#[test]
fn missing_record_keeps_path_off_by_default() {
    let registry = gated_registry(DaemonLinuxPreadmission::from_parts(None, facts()));
    let (request, admission) = verified_frames();
    let error = registry
        .register(
            request,
            admission,
            context(),
            100_000,
            ProviderCredentialProviderV2::DeepSeek,
        )
        .expect_err("default OFF denies");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::Unsupported
    ));
}

#[test]
fn copied_record_on_mismatched_installation_denies() {
    let registry = gated_registry(DaemonLinuxPreadmission::from_parts(
        Some(record()),
        LinuxInstallationFacts {
            machine_id_digest: [9; 32],
            ..facts()
        },
    ));
    let (request, admission) = verified_frames();
    let error = registry
        .register(
            request,
            admission,
            context(),
            100_000,
            ProviderCredentialProviderV2::DeepSeek,
        )
        .expect_err("copied record denies");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::Unsupported
    ));
}
#[test]
fn catalog_activation_admits_all_catalog_providers_before_broker_transfer() {
    for entry in runne_api::provider_catalog() {
        let record = LinuxEnrollmentActivationRecord {
            provider_scope: runne_api::provider_credential_enrollment::linux_activation_policy::LinuxEnrollmentScope::Catalog,
            ..record()
        };
        let registry = gated_registry(DaemonLinuxPreadmission::from_parts(Some(record), facts()));
        let (request, admission) = verified_frames();
        registry
            .register(
                request,
                admission,
                context(),
                100_000,
                entry.provider_id.parse().unwrap(),
            )
            .unwrap_or_else(|error| panic!("{}: {error:?}", entry.provider_id));
    }
}

#[test]
fn legacy_record_does_not_gain_catalog_scope() {
    for entry in runne_api::provider_catalog()
        .iter()
        .filter(|entry| entry.provider_id != "deepseek")
    {
        let registry = gated_registry(DaemonLinuxPreadmission::from_parts(Some(record()), facts()));
        let (request, admission) = verified_frames();
        assert!(
            matches!(
                registry.register(
                    request,
                    admission,
                    context(),
                    100_000,
                    entry.provider_id.parse().unwrap()
                ),
                Err(ProviderCredentialEnrollmentHostError::Unsupported)
            ),
            "{}",
            entry.provider_id
        );
    }
}
