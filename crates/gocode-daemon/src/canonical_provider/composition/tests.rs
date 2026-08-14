use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gocode_api::CreateConversationInput;
use gocode_api::{
    OperationalTelemetryQueryErrorV1, OperationalTelemetryQueryPort, ProviderActivationBindingV1,
    RecoveryObservationStatusV1,
};
use gocode_application::commands::BeginConversationTextInput;
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use gocode_application::ports::{
    ApplicationCommandContext, Clock, ClockError, PrincipalId, RuntimeAuthorityId,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::provider::ProviderExecutionStore;
use gocode_domain::timestamp::Timestamp;
use gocode_domain::{
    event::Actor,
    id::{IdempotencyKey, WorkspaceId},
    message::MessageText,
};
use gocode_runtime::provider_execution::ProviderTerminalPersistence;
use gocode_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};
use gocode_security::SecretBroker;
use gocode_store::store::StoreTransaction;

use super::*;
use crate::application::VerifiedOwnerPrivateConfig;
use crate::bootstrap::bootstrap;
use crate::config::BuiltInDefaults;
use crate::operational_telemetry::DaemonOperationalTelemetryQueryService;
use crate::operational_telemetry::compose_operational_telemetry_query;
use crate::provider_activation::ProviderActivation;

mod pending;
mod recovery_audit;
mod workspace;
use workspace::seed_canonical_workspace;

fn managed_test_connection(path: &str) -> gocode_store::schema::ManagedConnection {
    let observer = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let authority = gocode_store::schema::read_authority_id(&observer)
        .unwrap()
        .unwrap();
    let lineage = gocode_store::schema::read_event_log_lineage_id(&observer)
        .unwrap()
        .unwrap();
    drop(observer);
    gocode_store::schema::reopen_managed_connection_validated(
        std::path::Path::new(path),
        gocode_store::schema::ConnectionMode::ValidatedReopen,
        |connection| {
            if gocode_store::schema::read_authority_id(connection)? == Some(authority)
                && gocode_store::schema::read_event_log_lineage_id(connection)? == Some(lineage)
            {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        },
    )
    .unwrap()
}

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Result<Timestamp, ClockError> {
        Ok(Timestamp::from_unix_micros(1_000_000))
    }
}

#[derive(Default)]
struct Keyring(Mutex<HashMap<ProviderJournalKeyRef, [u8; 32]>>);

impl ProviderJournalKeyring for Keyring {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn provider_journal_key_status(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        Ok(if self.0.lock().unwrap().contains_key(&key) {
            ProviderJournalKeyStatus::Available
        } else {
            ProviderJournalKeyStatus::Missing
        })
    }

    fn store_provider_journal_key(
        &self,
        key: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        self.0
            .lock()
            .unwrap()
            .insert(key.key_ref(), key.with_bytes(|bytes| *bytes));
        Ok(())
    }

    fn load_provider_journal_key(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        let bytes = self
            .0
            .lock()
            .unwrap()
            .get(&key)
            .copied()
            .ok_or(SecureStoreError::ProviderJournalKeyNotFound)?;
        ProviderJournalKeyMaterial::new(key, bytes)
    }

    fn delete_provider_journal_key(
        &self,
        _: ProviderJournalKeyRef,
        _: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::DeletionDenied)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn composed_service_keeps_recovery_state_when_telemetry_generation_is_mismatched() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::config::ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(
        directory.path(),
    ));
    config.provider_activation =
        ProviderActivation::from_binding(ProviderActivationBindingV1::openai_responses_text_v1());
    let profile_digest = *config.provider_activation.binding().profile_digest();
    let db_path = config.db_path.clone();
    let bootstrap = bootstrap(&config).unwrap();
    gocode_store::schema::ensure_event_log_lineage_id(&bootstrap.db_conn).unwrap();
    let authority = bootstrap.authority_id;
    let generation = bootstrap.launch_generation;
    let provenance = DaemonActivationProvenance::from_verified_owner_private_config(
        &VerifiedOwnerPrivateConfig::from_test_parts(config, bootstrap),
    );
    let prohibited: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let store = StoreTransaction::open(
        &db_path,
        RuntimeAuthorityId(hex::encode(authority)),
        Arc::clone(&prohibited),
    )
    .unwrap();
    let conversation_service: Arc<dyn ConversationTextCommandService> =
        Arc::new(ConversationTextService::new(
            store.clone(),
            store.clone(),
            RuntimeAuthorityId(hex::encode(authority)),
            Arc::clone(&prohibited),
        ));
    seed_canonical_workspace(
        &store,
        "018f2e3a-7000-7000-8000-000000000093".parse().unwrap(),
    );
    let conversation_id = "018f2e3a-7000-7000-8000-000000000091".parse().unwrap();
    let create_context = command_context("018f2e3a-7000-7000-8000-000000000092", "create");
    ConversationService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(hex::encode(authority)),
    )
    .create_from_application(
        &create_context,
        CreateConversationInput {
            conversation_id,
            workspace_id: "018f2e3a-7000-7000-8000-000000000093"
                .parse::<WorkspaceId>()
                .unwrap(),
            command_id: create_context.command_id,
            idempotency_key: create_context.idempotency_key.clone(),
        },
    )
    .unwrap();
    let started = conversation_service
        .begin_text(
            &command_context("018f2e3a-7000-7000-8000-000000000094", "begin"),
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("fixture input").unwrap(),
            },
        )
        .unwrap();
    let keyring: Arc<dyn ProviderJournalKeyring> = Arc::new(Keyring::default());
    let effect = gocode_daemon_openai_effect::effect_from_loopback_fixture(reqwest::Client::new())
        .unwrap()
        .0;
    let decorator = Arc::new(|store: Arc<SqliteProviderExecutionStore>, _: u64| {
        let execution: Arc<dyn ProviderExecutionStore> = store.clone();
        let terminal: Arc<dyn ProviderTerminalPersistence> = store;
        (execution, terminal)
    });
    let service = DaemonCanonicalOpenAiService::compose(DaemonCanonicalOpenAiComposition {
        db_path: db_path.clone(),
        dispatch_connection: managed_test_connection(&db_path),
        execution_connection: managed_test_connection(&db_path),
        credential_connection: managed_test_connection(&db_path),
        runtime_authority_id: authority,
        runtime_generation: generation,
        activation_provenance: provenance,
        expected_profile_digest: profile_digest,
        conversation_store: store,
        conversation_service,
        prohibited_content: prohibited,
        dependencies: ProtectedProviderDependencyCapsule::from_loopback_fixture(
            effect,
            keyring,
            decorator,
            Arc::new(crate::canonical_provider::credential_versions::fixture_native),
        ),
    })
    .await
    .unwrap();

    let registry = service.recovery_observation_registry();
    let before = registry.snapshot_recovery_observation();
    let unavailable = compose_operational_telemetry_query(Some(&service), generation + 1);
    assert!(matches!(
        unavailable.query_operational_telemetry(),
        Err(OperationalTelemetryQueryErrorV1::Unavailable)
    ));
    let after = registry.snapshot_recovery_observation();
    assert!(after.availability() == before.availability());
    assert_eq!(after.observed_count(), before.observed_count());
    assert_eq!(after.dropped_event_count(), before.dropped_event_count());
    assert_eq!(
        after.drop_counter_saturated(),
        before.drop_counter_saturated()
    );

    pending::create(&service, started).await;
    service.recover_pending().await.unwrap();
    let query = DaemonOperationalTelemetryQueryService::new(
        service.operational_telemetry_store(),
        service.recovery_observation_registry(),
        Arc::new(FixedClock),
        match service.telemetry_launch_context(generation) {
            Ok(launch) => launch,
            Err(_) => panic!("composed launch context must be valid"),
        },
    );

    assert!(matches!(
        query
            .query_operational_telemetry()
            .unwrap()
            .recovery_transient()
            .status(),
        RecoveryObservationStatusV1::LowerBoundSinceLaunch
    ));
    assert_eq!(
        query
            .query_operational_telemetry()
            .unwrap()
            .recovery_transient()
            .observed_outbox_recoveries_in_generation(),
        Some(1)
    );
}

fn command_context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("test").unwrap(),
    }
}
