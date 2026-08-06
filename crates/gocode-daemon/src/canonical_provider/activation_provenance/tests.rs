use super::*;
use crate::application::VerifiedOwnerPrivateConfig;
use crate::bootstrap::bootstrap;
use crate::config::{BuiltInDefaults, ConfigurationSnapshot};
#[cfg(unix)]
use crate::protected_activation::VerifiedProtectedApplicationStart;
use crate::provider_activation::ProviderActivation;
use gocode_api::ProviderActivationBindingV1;
use gocode_application::provider::{ProviderAdmissionError, ProviderLeaseBindingKind};
use gocode_store::provider::{ProviderRuntimeAuthorityConfig, SqliteProviderExecutionStore};

fn owner_token(
    activation: ProviderActivation,
    config_digest: &str,
    authority: [u8; 16],
    generation: u64,
) -> (tempfile::TempDir, VerifiedOwnerPrivateConfig) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(directory.path()));
    config.provider_activation = activation;
    config.digest = config_digest.into();
    let mut bootstrap = bootstrap(&config).unwrap();
    bootstrap.authority_id = authority;
    bootstrap.launch_generation = generation;
    bootstrap.launch_identity =
        crate::launch_identity::LaunchIdentity::generate(generation).unwrap();
    (
        directory,
        VerifiedOwnerPrivateConfig::from_test_parts(config, bootstrap),
    )
}

fn openai_activation() -> ProviderActivation {
    ProviderActivation::from_binding(ProviderActivationBindingV1::openai_responses_text_v1())
}

fn authority_config(provenance: DaemonActivationProvenance) -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [0x11; 16],
        database_generation: 1,
        principal_id: "local-owner".into(),
        owner_id: "owner".into(),
        scope: "provider.openai.responses.text".into(),
        generation: 1,
        fencing_token: 1,
        capability_grant_id: "capability".into(),
        capability_revision: 1,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval".into(),
        approval_revision: 1,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [0x21; 32],
        pricing_revision_digest: [0x22; 32],
        activation_binding_kind: provenance.kind(),
        activation_binding_digest: provenance.digest(),
        token_budget_limit: 1_000,
        cost_budget_limit_micros: 1_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}

#[cfg(unix)]
fn protected_token() -> (tempfile::TempDir, VerifiedProtectedApplicationStart) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(directory.path()));
    config.provider_activation = openai_activation();
    let mut bootstrap = bootstrap(&config).unwrap();
    bootstrap.authority_id = [0x11; 16];
    (
        directory,
        VerifiedProtectedApplicationStart::from_test_parts(config, openai_activation(), bootstrap),
    )
}

#[test]
fn external_provenance_changes_only_for_stable_bound_inputs() {
    let activation = openai_activation();
    let (_base_dir, base) = owner_token(activation.clone(), "config-a", [0x11; 16], 1);
    let (_volatile_dir, volatile) = owner_token(activation.clone(), "config-a", [0x11; 16], 2);
    let (_authority_dir, authority) = owner_token(activation.clone(), "config-a", [0x12; 16], 1);
    let (_mode_dir, mode) = owner_token(
        ProviderActivation::deterministic_v1(),
        "config-a",
        [0x11; 16],
        1,
    );
    let (_mode_profile_dir, mode_profile) = owner_token(
        ProviderActivation::deterministic_v1(),
        "config-a",
        [0x11; 16],
        1,
    );
    let (_config_dir, config) = owner_token(activation, "config-b", [0x11; 16], 1);

    let base = DaemonActivationProvenance::from_verified_owner_private_config(&base);
    assert_eq!(base.kind(), ProviderLeaseBindingKind::ExternalOwnerPrivate);
    assert_eq!(
        base.digest(),
        DaemonActivationProvenance::from_verified_owner_private_config(&volatile).digest()
    );
    assert_ne!(
        base.digest(),
        DaemonActivationProvenance::from_verified_owner_private_config(&authority).digest()
    );
    assert_ne!(
        base.digest(),
        DaemonActivationProvenance::from_verified_owner_private_config(&mode).digest()
    );
    assert_ne!(
        base.digest(),
        DaemonActivationProvenance::from_verified_owner_private_config(&mode_profile).digest()
    );
    assert_ne!(
        base.digest(),
        DaemonActivationProvenance::from_verified_owner_private_config(&config).digest()
    );
}

#[cfg(unix)]
#[test]
fn protected_provenance_uses_the_protected_kind() {
    let (directory, start) = protected_token();
    let provenance = DaemonActivationProvenance::from_verified_protected_launch(&start);

    assert_eq!(provenance.kind(), ProviderLeaseBindingKind::ProtectedV2);
    drop(directory);
}

#[test]
fn daemon_derived_binding_rejects_mutation_without_durable_effect() {
    let (directory, token) = owner_token(openai_activation(), "config-a", [0x11; 16], 1);
    let provenance = DaemonActivationProvenance::from_verified_owner_private_config(&token);
    let path = directory.path().join("authority.sqlite");
    let store = SqliteProviderExecutionStore::open(&path).unwrap();
    let config = authority_config(provenance);
    store.install_runtime_authority(&config).unwrap();
    let original: (String, Vec<u8>) = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT activation_binding_kind, activation_binding_digest
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut mutated = config.clone();
    mutated.activation_binding_digest[0] ^= 0xff;

    assert_eq!(
        store.install_runtime_authority(&mutated),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    assert_eq!(store.admitted_count().unwrap(), 0);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let after: (String, Vec<u8>, i64) = connection
        .query_row(
            "SELECT activation_binding_kind, activation_binding_digest,
                    (SELECT COUNT(*) FROM provider_effect_starts)
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((after.0, after.1), original);
    assert_eq!(after.2, 0);
}

#[test]
fn external_digest_cannot_be_relabelled_as_protected_without_effect() {
    let (directory, token) = owner_token(openai_activation(), "config-a", [0x11; 16], 1);
    let path = directory.path().join("authority.sqlite");
    let store = SqliteProviderExecutionStore::open(&path).unwrap();
    let config =
        authority_config(DaemonActivationProvenance::from_verified_owner_private_config(&token));
    store.install_runtime_authority(&config).unwrap();
    let mut mutated = config;
    mutated.activation_binding_kind = ProviderLeaseBindingKind::ProtectedV2;

    assert_eq!(
        store.install_runtime_authority(&mutated),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    assert_eq!(store.admitted_count().unwrap(), 0);
    assert_eq!(effect_count(&path), 0);
}

#[cfg(unix)]
#[test]
fn protected_digest_cannot_be_relabelled_as_external_without_effect() {
    let (directory, start) = protected_token();
    let path = directory.path().join("authority.sqlite");
    let store = SqliteProviderExecutionStore::open(&path).unwrap();
    let config = authority_config(DaemonActivationProvenance::from_verified_protected_launch(
        &start,
    ));
    store.install_runtime_authority(&config).unwrap();
    let mut mutated = config;
    mutated.activation_binding_kind = ProviderLeaseBindingKind::ExternalOwnerPrivate;

    assert_eq!(
        store.install_runtime_authority(&mutated),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    assert_eq!(store.admitted_count().unwrap(), 0);
    assert_eq!(effect_count(&path), 0);
}

fn effect_count(path: &std::path::Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM provider_effect_starts", [], |row| {
            row.get(0)
        })
        .unwrap()
}
