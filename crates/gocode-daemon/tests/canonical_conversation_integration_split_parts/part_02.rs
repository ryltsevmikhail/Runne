#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_generation_is_authenticated_idempotent_durable_and_queryable_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let config = test_config(&directory);
    let daemon = start(&config).await;
    let TestSession {
        client,
        authorization,
    } = connect_session(&config).await;
    let token = hex::encode(std::fs::read(&config.replay_integrity_key_path).unwrap());
    let client_profile_path =
        PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");
    #[cfg(unix)]
    {
        let local_profile =
            gocode_runtime_client::LocalRuntimeProfile::load(&client_profile_path).unwrap();
        assert_eq!(local_profile.endpoint().address(), daemon.address);
    }
    assert!(
        !std::fs::read_to_string(&client_profile_path)
            .unwrap()
            .contains(&token),
        "published profile must reference, not contain, the credential"
    );

    let unauthorized_profile = client
        .get(url(daemon.address, "/v1/runtime/profile"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized_profile.status(), StatusCode::UNAUTHORIZED);

    let runtime_profile = client
        .get(url(daemon.address, "/v1/runtime/profile"))
        .header("authorization", &authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(runtime_profile.status(), StatusCode::OK);
    let runtime_profile = runtime_profile.json::<Value>().await.unwrap();
    assert_eq!(
        runtime_profile["profileId"],
        gocode_runtime::bundle::BUNDLE_ID
    );
    assert_eq!(
        runtime_profile["schemaHash"],
        "fa05104a8400cd7279a02210489df1d2a958e3e040a384d2a6d7ea6ce522b6ad"
    );
    assert_eq!(runtime_profile["runtimeVersion"], env!("CARGO_PKG_VERSION"));
    assert_eq!(runtime_profile["launchGeneration"], 1);

    let unauthorized = command(
        &client,
        &daemon,
        None,
        "/v1/conversations",
        CREATE_COMMAND_ID,
        "conversation-create",
        json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        }),
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let event_count: i64 = Connection::open(&config.db_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(event_count, 0, "rejected auth must commit no event");

    let created = command(
        &client,
        &daemon,
        Some(&authorization),
        "/v1/conversations",
        CREATE_COMMAND_ID,
        "conversation-create",
        json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        }),
    )
    .await;
    assert_eq!(created.status(), StatusCode::ACCEPTED);
    let created: Value = created.json().await.unwrap();
    assert_eq!(created["conversationId"], CONVERSATION_ID);
    assert_eq!(created["workspaceId"], WORKSPACE_ID);
    assert_eq!(created["streamVersion"], 1);

    let generated = command(
        &client,
        &daemon,
        Some(&authorization),
        &format!("/v1/conversations/{CONVERSATION_ID}/messages"),
        GENERATE_COMMAND_ID,
        "generate-one",
        json!({
            "expectedVersion": 1,
            "text": "hello",
        }),
    )
    .await;
    assert_eq!(generated.status(), StatusCode::OK);
    let generated: Value = generated.json().await.unwrap();
    assert_eq!(generated["conversationId"], CONVERSATION_ID);
    assert_eq!(generated["conversationStreamVersion"], 3);
    assert_eq!(generated["taskRunStreamVersion"], 5);
    assert_eq!(generated["userMessage"]["role"], "user");
    assert_eq!(generated["userMessage"]["text"], "hello");
    assert_eq!(generated["assistantMessage"]["role"], "assistant");
    assert_eq!(
        generated["assistantMessage"]["text"],
        "GOCODE local response: hello"
    );
    assert_eq!(
        generated["userMessage"]["taskRunId"],
        generated["taskRunId"]
    );
    assert_eq!(
        generated["assistantMessage"]["taskRunId"],
        generated["taskRunId"]
    );

    let (status, timeline) = messages(&client, &daemon, &authorization).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(timeline["conversationId"], CONVERSATION_ID);
    assert_eq!(timeline["streamVersion"], 3);
    assert_eq!(timeline["messages"].as_array().unwrap().len(), 2);
    assert_eq!(timeline["messages"][0], generated["userMessage"]);
    assert_eq!(timeline["messages"][1], generated["assistantMessage"]);

    let retried = command(
        &client,
        &daemon,
        Some(&authorization),
        &format!("/v1/conversations/{CONVERSATION_ID}/messages"),
        GENERATE_COMMAND_ID,
        "generate-one",
        json!({
            "expectedVersion": 1,
            "text": "hello",
        }),
    )
    .await;
    assert_eq!(retried.status(), StatusCode::OK);
    assert_eq!(retried.json::<Value>().await.unwrap(), generated);

    let conflict = command(
        &client,
        &daemon,
        Some(&authorization),
        &format!("/v1/conversations/{CONVERSATION_ID}/messages"),
        "018f2e3a-7000-7000-8000-000000000085",
        "generate-one",
        json!({
            "expectedVersion": 1,
            "text": "changed",
        }),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        conflict.json::<Value>().await.unwrap()["code"],
        "conversation_conflict"
    );

    let oversized = command(
        &client,
        &daemon,
        Some(&authorization),
        &format!("/v1/conversations/{CONVERSATION_ID}/messages"),
        "018f2e3a-7000-7000-8000-000000000086",
        "generate-oversized",
        json!({
            "expectedVersion": 3,
            "text": "x".repeat(65_537),
        }),
    )
    .await;
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oversized.json::<Value>().await.unwrap()["code"],
        "message_text_too_large"
    );
    let connection = Connection::open(&config.db_path).unwrap();
    let event_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    let sensitive_event_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM events WHERE sensitivity = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        event_count, 8,
        "duplicate, conflict, and rejected input must append no events"
    );
    assert_eq!(
        sensitive_event_count, 2,
        "only the user and assistant message events are sensitive"
    );

    let taskrun_id = generated["taskRunId"].as_str().unwrap().to_owned();
    let taskrun = client
        .get(url(daemon.address, &format!("/v1/task-runs/{taskrun_id}")))
        .header("authorization", &authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(taskrun.status(), StatusCode::OK);
    let taskrun: Value = taskrun.json().await.unwrap();
    assert_eq!(taskrun["state"], "succeeded");
    assert_eq!(taskrun["streamVersion"], 5);

    daemon.stop().await;
    assert!(
        !client_profile_path.exists(),
        "clean shutdown must remove only its published connection profile"
    );

    let restarted = start(&config).await;
    let TestSession {
        client: restarted_client,
        authorization: restarted_authorization,
    } = connect_session(&config).await;
    let (status, restored) =
        messages(&restarted_client, &restarted, &restarted_authorization).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(restored, timeline);
    let restored_taskrun = restarted_client
        .get(url(
            restarted.address,
            &format!("/v1/task-runs/{taskrun_id}"),
        ))
        .header("authorization", &restarted_authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(restored_taskrun.status(), StatusCode::OK);
    assert_eq!(
        restored_taskrun.json::<Value>().await.unwrap()["state"],
        "succeeded"
    );
    restarted.stop().await;
}
