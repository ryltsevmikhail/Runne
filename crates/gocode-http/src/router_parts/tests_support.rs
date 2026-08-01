    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use gocode_api::{
        ApiActor, ApiPrincipalId, CompleteTaskRunCommand, ConversationCommandContext,
        ConversationCommandHostPort, ConversationCreatedAck, ConversationHostError,
        ConversationMessagesSnapshot, ConversationQueryHostPort, ConversationTextResult,
        CreateCanonicalConversationCommand, CreateTaskRunCommand, DaemonInstanceId,
        ExistingTaskRunCommand, GenerateConversationTextCommand, StableRuntimeBinding,
        TaskRunCommandAck, TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError,
        TaskRunQueryHostPort, TaskRunSnapshot,
    };
    use gocode_application::local_session::{LocalSessionService, bootstrap_proof_transcript};
    use gocode_application::ports::{
        ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
    };
    use gocode_application::prohibited_content::{
        CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
    };
    use gocode_application::replay_service::ReplayService;
    use gocode_domain::{
        event::Sensitivity,
        id::{ConversationId, EventLogLineageId, TaskRunId},
    };
    use gocode_store::{replay_store::ReplayStore, schema::apply_migrations};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use tower::ServiceExt;

    const CAPABILITIES: &[&str] = &["conversation.create.v1", "conversation.list.v1"];

    struct AvailableGuard;

    struct AvailableReplayAuthorization;

    impl ReplayAuthorizationPort for AvailableReplayAuthorization {
        fn current_lease(
            &self,
            request: &ReplayAuthorizationRequest,
        ) -> Result<ReplayAuthorizationLease, ReplayError> {
            ReplayAuthorizationLease::new(
                request.principal_id.clone(),
                request.expected_epoch,
                Sensitivity::Internal,
            )
        }
    }

    impl ProhibitedContentPort for AvailableGuard {
        fn inspect(
            &self,
            _boundary: CanonicalContentBoundary,
            _bytes: &[u8],
        ) -> Result<ContentDisposition, ContentGuardError> {
            Ok(ContentDisposition::Allowed { policy_epoch: 1 })
        }
    }

    #[derive(Clone)]
    struct UnavailableTaskRunHost;

    impl TaskRunCommandHostPort for UnavailableTaskRunHost {
        async fn create_task_run(
            &self,
            _: TaskRunCommandContext,
            _: CreateTaskRunCommand,
        ) -> Result<TaskRunCommandAck, TaskRunHostError> {
            Err(TaskRunHostError::Unavailable)
        }

        async fn queue_task_run(
            &self,
            _: TaskRunCommandContext,
            _: ExistingTaskRunCommand,
        ) -> Result<TaskRunCommandAck, TaskRunHostError> {
            Err(TaskRunHostError::Unavailable)
        }

        async fn admit_task_run(
            &self,
            _: TaskRunCommandContext,
            _: ExistingTaskRunCommand,
        ) -> Result<TaskRunCommandAck, TaskRunHostError> {
            Err(TaskRunHostError::Unavailable)
        }

        async fn start_attempt(
            &self,
            _: TaskRunCommandContext,
            _: ExistingTaskRunCommand,
        ) -> Result<TaskRunCommandAck, TaskRunHostError> {
            Err(TaskRunHostError::Unavailable)
        }

        async fn complete_task_run(
            &self,
            _: TaskRunCommandContext,
            _: CompleteTaskRunCommand,
        ) -> Result<TaskRunCommandAck, TaskRunHostError> {
            Err(TaskRunHostError::Unavailable)
        }
    }

    impl TaskRunQueryHostPort for UnavailableTaskRunHost {
        async fn get_task_run(&self, _: TaskRunId) -> Result<TaskRunSnapshot, TaskRunHostError> {
            Err(TaskRunHostError::Unavailable)
        }
    }

    #[derive(Clone)]
    struct UnavailableConversationHost;

    impl ConversationCommandHostPort for UnavailableConversationHost {
        async fn create_conversation(
            &self,
            _: ConversationCommandContext,
            _: CreateCanonicalConversationCommand,
        ) -> Result<ConversationCreatedAck, ConversationHostError> {
            Err(ConversationHostError::Unavailable)
        }

        async fn generate_text(
            &self,
            _: ConversationCommandContext,
            _: GenerateConversationTextCommand,
        ) -> Result<ConversationTextResult, ConversationHostError> {
            Err(ConversationHostError::Unavailable)
        }
    }

    impl ConversationQueryHostPort for UnavailableConversationHost {
        async fn list_messages(
            &self,
            _: ConversationId,
        ) -> Result<ConversationMessagesSnapshot, ConversationHostError> {
            Err(ConversationHostError::Unavailable)
        }
    }

    fn binding() -> gocode_api::RuntimeSessionBinding {
        gocode_api::RuntimeSessionBinding::new(
            StableRuntimeBinding::new(
                [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
                ApiPrincipalId::new("local-owner").unwrap(),
                "018f2e3a-7000-7000-8000-000000000003"
                    .parse::<EventLogLineageId>()
                    .unwrap(),
                "gocode-ui-client/1",
                [3; 32],
                crate::runtime_profile::ordered_capability_digest(CAPABILITIES),
            )
            .unwrap(),
            DaemonInstanceId::from_bytes([
                1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2,
            ]),
            7,
            [5; 16],
            3,
            Sensitivity::Internal,
            [6; 32],
        )
        .unwrap()
    }

    fn clock() -> Arc<dyn Fn() -> Duration + Send + Sync> {
        Arc::new(|| Duration::ZERO)
    }

    fn profile_state() -> RuntimeProfileHttpState {
        RuntimeProfileHttpState::new("legacy", "legacy", "0.1.0-test", CAPABILITIES)
    }

    fn replay_state() -> ReplayHttpState {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        apply_migrations(&connection).unwrap();
        let binding = binding();
        let service = ReplayService::new(
            Arc::new(ReplayStore::new(connection)),
            [11; 32],
            *binding.stable().lineage_id(),
            Arc::new(AvailableReplayAuthorization),
        );
        ReplayHttpState::new(
            service,
            crate::replay::ReplayHttpBinding::new(
                *binding.stable().authority_id(),
                i64::try_from(binding.ephemeral().launch_generation()).unwrap(),
                i64::try_from(binding.ephemeral().authorization_epoch()).unwrap(),
            )
            .unwrap(),
            crate::limits::LimitsConfig::default(),
            Arc::new(AvailableGuard),
        )
    }

    fn host() -> SecureLocalHttpHost {
        let binding = binding();
        let service = Arc::new(Mutex::new(LocalSessionService::new(
            binding.clone(),
            [7; 32],
        )));
        SecureLocalHttpHost::new(
            VerifiedLocalTls::from_verified_listener(),
            HealthState {
                recovery_state: crate::health::RecoveryState::Ready,
            },
            AdmissionState::new(crate::health::RecoveryState::Ready),
            service,
            binding,
            false,
            clock(),
            profile_state(),
            TaskRunHttpState::new(
                UnavailableTaskRunHost,
                ApiActor::new("gocode-http-test").unwrap(),
            ),
            ConversationHttpState::new(
                UnavailableConversationHost,
                ApiActor::new("gocode-http-test").unwrap(),
            ),
            replay_state(),
        )
        .unwrap()
    }
