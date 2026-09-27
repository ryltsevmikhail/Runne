use super::*;

#[test]
fn started_text_only_conversation_projects_provider_call() {
    let (_directory, database_path) = text_path_database("d13-text-only-projection");
    let authority = RuntimeAuthorityId("d13-text-only-projection".into());
    let store =
        StoreTransaction::open(&database_path, authority.clone(), text_path_guard()).unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8001-000000000901".parse().unwrap();
    let grouping_workspace_id: WorkspaceId =
        "018f2e3a-7000-7000-8002-000000000901".parse().unwrap();
    let create_context = text_path_context(901, "create-text-only-projection");
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create_context,
            CreateConversationInput {
                conversation_id,
                workspace_id: grouping_workspace_id,
                command_id: create_context.command_id,
                idempotency_key: create_context.idempotency_key.clone(),
                scope: runne_api::ConversationContextScope::TextOnly,
            },
        )
        .unwrap();

    let context = text_path_context(902, "generate-text-only-projection");
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("hello from a text-only chat").unwrap(),
    };
    let started =
        ConversationTextService::new(store.clone(), store.clone(), authority, text_path_guard())
            .begin(&context, original.clone())
            .unwrap();
    assert_eq!(started.phase, TextGenerationPhase::Started);

    let job = CanonicalProviderExecutionJob {
        context,
        original,
        started,
    };
    let profile = runne_provider_deepseek::DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .unwrap();
    let call = project_call(
        &store,
        &job,
        &profile,
        "deepseek",
        runne_provider_deepseek::DEEPSEEK_MODEL_ID,
        runne_provider_deepseek::DEEPSEEK_MODEL_REVISION,
    )
    .expect("the started TextOnly stream should project for provider execution");
    assert_eq!(call.model_ref().provider_id().as_str(), "deepseek");
}
