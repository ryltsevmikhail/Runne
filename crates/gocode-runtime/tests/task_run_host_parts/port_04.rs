
#[tokio::test(flavor = "current_thread")]
async fn uncertain_provider_effect_preserves_started_generation_for_reconciliation() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory
        .path()
        .join("provider-uncertain.sqlite")
        .to_str()
        .unwrap()
        .to_owned();
    let authority = RuntimeAuthorityId("provider-uncertain-test".into());
    let store =
        StoreTransaction::open(&database_path, authority.clone(), available_guard()).unwrap();
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
    let guard = available_guard();
    let text_service: Arc<dyn ConversationTextCommandService> =
        Arc::new(ConversationTextService::new(
            store.clone(),
            store.clone(),
            authority.clone(),
            Arc::clone(&guard),
        ));
    let (handle, mut controller) = Runtime::start_borrowed_with_provider_conversations(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
        taskrun_service,
        text_service,
        Arc::new(UncertainProviderService),
        RuntimeConfig::default(),
    )
    .unwrap();
    let host = RuntimeCanonicalConversationHost::<_, _, _, DeterministicTextProvider>::new_provider(
        handle,
        Arc::new(ConversationService::new(
            store.clone(),
            store.clone(),
            authority,
        )),
        store.clone(),
        guard,
    );
    let conversation_id: ConversationId = CONVERSATION_ID.parse().unwrap();
    host.create_conversation(
        conversation_context(20, "create-provider-uncertain"),
        CreateCanonicalConversationCommand {
            conversation_id,
            workspace_id: WORKSPACE_ID.parse().unwrap(),
        },
    )
    .await
    .unwrap();

    assert_eq!(
        host.generate_text(
            conversation_context(21, "generate-provider-uncertain"),
            GenerateConversationTextCommand {
                conversation_id,
                expected_version: 1,
                text: CanonicalMessageText::new("maybe dispatched").unwrap(),
            },
        )
        .await,
        Err(ConversationHostError::ProviderOutputRejected)
    );
    let snapshot = host.list_messages(conversation_id).await.unwrap();
    assert_eq!(snapshot.stream_version, 2);
    assert_eq!(snapshot.messages.len(), 1);
    let conversation =
        Conversation::replay(&store.load_conversation(conversation_id).unwrap().events).unwrap();
    assert!(conversation.active_generation().is_some());
    let taskrun = TaskRun::replay(
        &store
            .load_task_run(snapshot.messages[0].taskrun_id)
            .unwrap()
            .events,
    )
    .unwrap();
    assert_eq!(taskrun.state(), TaskRunState::Running);

    assert_eq!(
        controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await,
        ShutdownOutcome::Quiesced
    );
}

#[tokio::test(flavor = "current_thread")]
async fn newly_prohibited_provider_input_is_rejected_before_provider_invocation() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory
        .path()
        .join("provider-input-rejection.sqlite")
        .to_str()
        .unwrap()
        .to_owned();
    let authority = RuntimeAuthorityId("provider-input-rejection-test".into());
    let store =
        StoreTransaction::open(&database_path, authority.clone(), available_guard()).unwrap();
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
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(ProviderInputRejectingGuard);
    let finish_calls = Arc::new(AtomicUsize::new(0));
    let text_service: Arc<dyn ConversationTextCommandService> =
        Arc::new(CountingConversationTextService {
            inner: ConversationTextService::new(
                store.clone(),
                store.clone(),
                authority.clone(),
                Arc::clone(&guard),
            ),
            finish_calls: Arc::clone(&finish_calls),
        });
    let (handle, mut controller) = Runtime::start_borrowed_with_conversations(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
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
    host.create_conversation(
        conversation_context(3, "create-provider-input-rejection"),
        CreateCanonicalConversationCommand {
            conversation_id,
            workspace_id: WORKSPACE_ID.parse().unwrap(),
        },
    )
    .await
    .unwrap();

    let generation_context = conversation_context(4, "generate-provider-input-rejection");
    let command = GenerateConversationTextCommand {
        conversation_id,
        expected_version: 1,
        text: CanonicalMessageText::new("accepted before policy change").unwrap(),
    };
    let first = host
        .generate_text(generation_context.clone(), command.clone())
        .await;
    let snapshot_after_first = host.list_messages(conversation_id).await.unwrap();
    let duplicate = host.generate_text(generation_context, command).await;

    assert_eq!(first, Err(ConversationHostError::ProhibitedSecretMaterial));
    assert_eq!(
        duplicate,
        Err(ConversationHostError::ProhibitedSecretMaterial)
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(finish_calls.load(Ordering::SeqCst), 1);
    let snapshot = host.list_messages(conversation_id).await.unwrap();
    assert_eq!(snapshot, snapshot_after_first);
    assert_eq!(snapshot.messages.len(), 1);
    assert_eq!(snapshot.stream_version, 3);
    assert_eq!(
        TaskRun::replay(
            &store
                .load_task_run(snapshot.messages[0].taskrun_id)
                .unwrap()
                .events
        )
        .unwrap()
        .state(),
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
