use std::path::Path;
use std::sync::Arc;

use runne_application::provider::{
    ProviderAuthorityIssueRequest, ProviderJournalKeyBinding, ProviderLeaseBindingKind,
};
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::{
    DispatchAttemptId, ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord,
    PreparedRequest, ProviderCall, ProviderCallId, ProviderId, ProviderRepositoryState,
    ProviderStreamId,
};
use runne_runtime::provider_execution::ProviderEventJournalContext;
use runne_store::provider::{
    MarkProviderStreaming, PreparedProviderRecord, ProviderAuthorityIssueOutcome,
    ProviderRuntimeAuthorityConfig, ProviderRuntimeLaunchCapability, SqliteProviderExecutionStore,
};

use crate::validated_reopen::ProviderTestDatabase;

use super::task5_support::{MemoryKeyring, SECRET};

pub(super) struct Task5ProductionFixture {
    database: ProviderTestDatabase,
    execution: Arc<SqliteProviderExecutionStore>,
    launch: ProviderRuntimeLaunchCapability,
    request: ProviderAuthorityIssueRequest,
    attempt: DispatchAttemptId,
    context: ProviderEventJournalContext,
    stream: ProviderStreamId,
    journal_key: ProviderJournalKeyBinding,
}

impl Task5ProductionFixture {
    pub(super) fn new(keyring: &MemoryKeyring) -> Self {
        let database = ProviderTestDatabase::new("provider-task5-production");
        let call = ProviderCall::new(
            ProviderCallId::from_bytes([4; 16]),
            ModelRef::new(
                ProviderId::new("fixture-provider").unwrap(),
                "fixture-model",
                "2026-08-08",
            )
            .unwrap(),
            [5; 32],
            1_024,
            serde_json::Value::Null,
        )
        .unwrap();
        let prepared = PreparedRequest::from_call(&call).unwrap();
        let prepared_record = PreparedProviderRecord {
            call_id: call.call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: [2; 32],
        };
        let execution = Arc::new(database.execution());
        let launch = execution
            .activate_runtime_launch(&runtime_authority())
            .unwrap();
        let dispatch = database.dispatch();
        dispatch
            .persist_prepared(&launch, &prepared_record)
            .unwrap();
        let journal_key = crate::online_proof::arm_with_keyring(execution.as_ref(), keyring, 7);
        let request = ProviderAuthorityIssueRequest {
            provider_id: call.model_ref().provider_id().clone(),
            principal_id: "principal-1".into(),
            conversation_id: ConversationId::from_bytes([6; 16]),
            taskrun_id: TaskRunId::from_bytes([7; 16]),
            execution_attempt_id: AttemptId::from_bytes([8; 16]),
            prepared: ContractPreparedProviderRecord {
                call_id: prepared_record.call_id,
                call_digest_version: prepared_record.call_digest_version,
                prepared_digest: prepared_record.prepared_digest,
                render_digest: prepared_record.render_digest,
                profile_digest: prepared_record.profile_digest,
            },
            pricing_revision_digest: [3; 32],
            requested_input_tokens: 512,
            requested_output_tokens: 1_024,
            max_cost_micros: 50_000,
            currency: "USD".into(),
            provider_idempotency_key: "provider-task5-production-1".into(),
        };
        let ProviderAuthorityIssueOutcome::Winner(admitted) =
            execution.issue(&launch, &request).unwrap()
        else {
            panic!("first issue must win")
        };
        let credential = crate::provider_credential_fixture::credential(
            &database,
            "fixture-provider",
            [1; 16],
            13,
            100,
        );
        let binding = credential
            .authorize_active(
                &ProviderId::new("fixture-provider").unwrap(),
                [1; 16],
                13,
                100,
            )
            .unwrap();
        let receipt = execution.start_effect(admitted.claim(), &binding).unwrap();
        assert!(receipt.matches_claim(admitted.claim()));
        let attempt = admitted.claim().attempt_id;
        let fencing_token = admitted.claim().fencing_token;
        let stream = ProviderStreamId::from_bytes([9; 16]);
        dispatch
            .mark_streaming(&MarkProviderStreaming {
                attempt_id: attempt,
                fencing_token,
                stream_id: stream,
            })
            .unwrap();
        let context = ProviderEventJournalContext {
            attempt_id: attempt,
            fencing_token,
            call_digest_version: prepared_record.call_digest_version,
            profile_digest: [2; 32],
            runtime_generation: 11,
        };
        Self {
            database,
            execution,
            launch,
            request,
            attempt,
            context,
            stream,
            journal_key,
        }
    }

    pub(super) fn path(&self) -> &Path {
        self.database.as_path()
    }

    pub(super) fn execution(&self) -> &SqliteProviderExecutionStore {
        self.execution.as_ref()
    }

    pub(super) const fn attempt(&self) -> DispatchAttemptId {
        self.attempt
    }

    pub(super) const fn context(&self) -> &ProviderEventJournalContext {
        &self.context
    }

    pub(super) const fn stream(&self) -> &ProviderStreamId {
        &self.stream
    }

    pub(super) const fn journal_key(&self) -> ProviderJournalKeyBinding {
        self.journal_key
    }

    pub(super) fn persisted_counts(&self) -> (i64, i64, i64, i64) {
        let connection = self.database.query_connection();
        let count = |table: &str| {
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        (
            count("provider_stream_journal"),
            count("provider_terminal_outbox"),
            count("events"),
            connection
                .query_row(
                    "SELECT COUNT(*) FROM provider_poll_flights
                     WHERE dispatch_attempt_id = ?1 AND cursor = 1",
                    [self.attempt.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .unwrap(),
        )
    }

    pub(super) fn effect_start_and_audit_counts(&self) -> (i64, i64) {
        self.database
            .query_connection()
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM provider_effect_starts
                     WHERE dispatch_attempt_id = ?1
                       AND provider_idempotency_key = ?2 AND state = 1),
                    (SELECT COUNT(*) FROM security_audit_pre_effect
                     WHERE intent_id = ('provider:' || lower(hex(?1)))
                       AND side_effect_started = 1)",
                rusqlite::params![
                    self.attempt.as_bytes().as_slice(),
                    self.request.provider_idempotency_key,
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    pub(super) fn dispatch_state(&self) -> ProviderRepositoryState {
        let connection = self.database.query_connection();
        match connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [self.attempt.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        {
            6 => ProviderRepositoryState::Uncertain,
            state => panic!("unexpected dispatch state {state}"),
        }
    }

    pub(super) fn retry_idempotency_state(&self) -> ProviderRepositoryState {
        match self.execution.issue(&self.launch, &self.request).unwrap() {
            ProviderAuthorityIssueOutcome::Existing { state } => state,
            ProviderAuthorityIssueOutcome::Winner(_) => panic!("retry minted duplicate authority"),
        }
    }

    pub(super) fn assert_secret_absent_from_durable_files(&self) {
        for entry in std::fs::read_dir(self.path().parent().unwrap()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap_or_default();
            assert!(!bytes.windows(SECRET.len()).any(|window| window == SECRET));
        }
    }
}

fn runtime_authority() -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "principal-1".into(),
        owner_id: "runtime-owner-1".into(),
        scope: "provider.dispatch".into(),
        generation: 11,
        fencing_token: 13,
        capability_grant_id: "grant-provider-network-1".into(),
        capability_revision: 2,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval-provider-network-1".into(),
        approval_revision: 3,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        activation_binding_kind: ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}
