impl ProhibitedContentPort for ProviderInputRejectingGuard {
    fn inspect(
        &self,
        boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(match boundary {
            CanonicalContentBoundary::CanonicalMutation => {
                ContentDisposition::Allowed { policy_epoch: 1 }
            }
            CanonicalContentBoundary::OutboundDelivery => {
                ContentDisposition::Prohibited { policy_epoch: 2 }
            }
        })
    }
}

struct CountingConversationTextService {
    inner: ConversationTextService<StoreTransaction, StoreTransaction>,
    finish_calls: Arc<AtomicUsize>,
}

impl ConversationTextCommandService for CountingConversationTextService {
    fn begin_text(
        &self,
        context: &ApplicationCommandContext,
        input: BeginConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        self.inner.begin_text(context, input)
    }

    fn finish_text(
        &self,
        context: &ApplicationCommandContext,
        input: FinishConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        self.finish_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.finish_text(context, input)
    }
}

#[derive(Clone)]
struct MarkerProvider {
    calls: Arc<AtomicUsize>,
}

struct UncertainProviderService;

impl CanonicalProviderExecutionService for UncertainProviderService {
    fn execute(
        &self,
        _job: CanonicalProviderExecutionJob,
    ) -> ProviderFuture<'_, Result<TextGenerationReceipt, CanonicalProviderExecutionError>> {
        Box::pin(async { Err(CanonicalProviderExecutionError::Uncertain) })
    }
}

impl LocalTextProvider for MarkerProvider {
    fn generate(&self, _input: &MessageText) -> Result<MessageText, LocalTextProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        MessageText::new(PROVIDER_MARKER).map_err(|_| LocalTextProviderError::InvalidOutput)
    }
}

fn conversation_context(sequence: u8, key: &str) -> ConversationCommandContext {
    ConversationCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000001{sequence:02x}")
            .parse()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("runne-cli").unwrap(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn prohibited_provider_output_is_rejected_durably_without_an_assistant_message() {
    let database = validated_reopen::ValidatedTestDatabase::new("provider-output-rejection");
    let authority = RuntimeAuthorityId("provider-output-rejection-test".into());
    let (store, _identity) =
        validated_reopen::initialize_store(database.path(), authority.clone(), available_guard())
            .unwrap();
    validated_reopen::seed_canonical_workspace(
        &store,
        "local-owner",
        WORKSPACE_ID.parse().unwrap(),
    );
    let taskrun_service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority.clone(),
    ));
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(MarkerGuard);
    let text_service: Arc<dyn ConversationTextCommandService> =
        Arc::new(ConversationTextService::new(
            store.clone(),
            store.clone(),
            authority.clone(),
            Arc::clone(&guard),
        ));
    let (handle, mut controller) = Runtime::start_borrowed_with_conversations(
        runne_runtime::TokioRuntimeContext::new_for_test(),
        taskrun_service,
        text_service,
        RuntimeConfig::default(),
    )
    .unwrap();
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let host = RuntimeCanonicalConversationHost::new(
        handle,
        Arc::new(ConversationService::new(
            store.clone(),
            store.clone(),
            authority,
        )),
        store.clone(),
        MarkerProvider {
            calls: Arc::clone(&provider_calls),
        },
        guard,
    );
    let conversation_id: ConversationId = CONVERSATION_ID.parse().unwrap();
    let workspace_id: WorkspaceId = WORKSPACE_ID.parse().unwrap();
    host.create_conversation(
        conversation_context(1, "create-provider-rejection"),
        CreateCanonicalConversationCommand {
            conversation_id,
            workspace_id,
        },
    )
    .await
    .unwrap();
    let generation_context = conversation_context(2, "generate-provider-rejection");
    let command = GenerateConversationTextCommand {
        conversation_id,
        expected_version: 1,
        text: CanonicalMessageText::new("ordinary user input").unwrap(),
    };

    let first = host
        .generate_text(generation_context.clone(), command.clone())
        .await;
    let duplicate = host.generate_text(generation_context, command).await;

    assert_eq!(first, Err(ConversationHostError::ProviderOutputRejected));
    assert_eq!(
        duplicate,
        Err(ConversationHostError::ProviderOutputRejected)
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert!(!format!("{first:?}").contains(PROVIDER_MARKER));

    let snapshot = host.list_messages(conversation_id).await.unwrap();
    assert_eq!(snapshot.stream_version, 3);
    assert_eq!(snapshot.messages.len(), 1);
    let conversation =
        Conversation::replay(&store.load_conversation(conversation_id).unwrap().events).unwrap();
    assert_eq!(conversation.active_generation(), None);

    let taskrun_id = snapshot.messages[0].taskrun_id;
    let taskrun_stream = store.load_task_run(taskrun_id).unwrap();
    assert!(matches!(
        taskrun_stream.events.last().unwrap().payload(),
        TaskRunEvent::TaskRunFailed { reason } if reason == "provider_output_rejected"
    ));
    assert_eq!(
        TaskRun::replay(&taskrun_stream.events).unwrap().state(),
        TaskRunState::Failed
    );

    assert_eq!(
        controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await,
        ShutdownOutcome::Quiesced
    );
}
