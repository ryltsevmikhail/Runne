#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_replay_handoff_delivers_conversation_created_over_sse() {
    let directory = tempfile::tempdir().unwrap();
    let config = test_config(&directory);
    let daemon = start(&config).await;
    let TestSession {
        client,
        authorization,
    } = connect_session(&config).await;
    support::seed_project_workspace(
        &client,
        daemon.address,
        &authorization,
        PROJECT_ID,
        WORKSPACE_ID,
    )
    .await;
    support::grant_project_trust(&config, PROJECT_ID);
    let aggregate_id = hex::encode(uuid::Uuid::parse_str(CONVERSATION_ID).unwrap().as_bytes());
    let opened = client
        .post(url(daemon.address, "/v1/replay/open-session"))
        .header("authorization", &authorization)
        .json(&json!({
            "aggregateType": "conversation",
            "aggregateId": aggregate_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::OK);
    let opened = opened.json::<Value>().await.unwrap();
    assert_eq!(opened["events"], json!([]));
    assert_eq!(opened["hasMore"], false);
    let session_id = opened["sessionId"].as_str().unwrap();
    let completed = client
        .post(url(
            daemon.address,
            &format!("/v1/replay/{session_id}/complete-catch-up"),
        ))
        .header("authorization", &authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let continued = client
        .post(url(
            daemon.address,
            &format!("/v1/replay/{session_id}/continue-live"),
        ))
        .header("authorization", &authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(continued.status(), StatusCode::OK);

    let mut stream = client
        .get(url(
            daemon.address,
            &format!("/v1/replay/{session_id}/events"),
        ))
        .header("authorization", &authorization)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), StatusCode::OK);

    let created = command(
        &client,
        &daemon,
        Some(&authorization),
        "/v1/conversations",
        CREATE_COMMAND_ID,
        "replay-conversation-create",
        json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        }),
    )
    .await;
    assert_eq!(created.status(), StatusCode::ACCEPTED);

    let delivery = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let chunk = stream
                .chunk()
                .await
                .unwrap()
                .expect("SSE stream must remain open");
            let chunk = String::from_utf8(chunk.to_vec()).unwrap();
            if chunk.contains("event: delivery") {
                break chunk;
            }
        }
    })
    .await
    .expect("live Conversation event must arrive before timeout");

    assert!(delivery.contains("\"aggregateType\":\"conversation\""));
    assert!(delivery.contains(&format!("\"aggregateId\":\"{CONVERSATION_ID}\"")));
    assert!(delivery.contains("\"eventType\":\"conversation.created\""));
    assert!(delivery.contains("\"replayCursor\":\"gocode-replay-cursor-v1."));

    drop(stream);
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acknowledged_replay_cursor_reopens_inclusively_after_daemon_restart() {
    let directory = tempfile::tempdir().unwrap();
    let config = test_config(&directory);
    let daemon = start(&config).await;
    let TestSession {
        client,
        authorization,
    } = connect_session(&config).await;
    support::seed_project_workspace(
        &client,
        daemon.address,
        &authorization,
        PROJECT_ID,
        WORKSPACE_ID,
    )
    .await;
    support::grant_project_trust(&config, PROJECT_ID);
    let aggregate_id = hex::encode(uuid::Uuid::parse_str(CONVERSATION_ID).unwrap().as_bytes());

    let created = command(
        &client,
        &daemon,
        Some(&authorization),
        "/v1/conversations",
        CREATE_COMMAND_ID,
        "replay-restart-create",
        json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        }),
    )
    .await;
    assert_eq!(created.status(), StatusCode::ACCEPTED);
    drop(created);

    let opened = client
        .post(url(daemon.address, "/v1/replay/open-session"))
        .header("authorization", &authorization)
        .json(&json!({
            "aggregateType": "conversation",
            "aggregateId": aggregate_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::OK);
    let opened = opened.json::<Value>().await.unwrap();
    let old_session_id = opened["sessionId"].as_str().unwrap().to_owned();
    let acknowledged_cursor = opened["events"][0]["cursor"].as_str().unwrap().to_owned();

    let acknowledged = client
        .post(url(
            daemon.address,
            &format!("/v1/replay/{old_session_id}/acknowledge"),
        ))
        .header("authorization", &authorization)
        .json(&json!({"cursor": acknowledged_cursor}))
        .send()
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);
    drop(acknowledged);
    drop(client);
    daemon.stop().await;

    let restarted = start(&config).await;
    let TestSession {
        client: restarted_client,
        authorization: restarted_authorization,
    } = connect_session(&config).await;
    let stale_session = restarted_client
        .post(url(
            restarted.address,
            &format!("/v1/replay/{old_session_id}/read-page"),
        ))
        .header("authorization", &restarted_authorization)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(stale_session.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        stale_session.json::<Value>().await.unwrap()["code"],
        "replay_session_not_found"
    );

    let reopened = restarted_client
        .post(url(restarted.address, "/v1/replay/open-session"))
        .header("authorization", &restarted_authorization)
        .json(&json!({
            "aggregateType": "conversation",
            "aggregateId": aggregate_id,
            "fromCursor": acknowledged_cursor,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reopened.status(), StatusCode::OK);
    let reopened = reopened.json::<Value>().await.unwrap();
    assert_eq!(reopened["events"].as_array().unwrap().len(), 1);
    assert_eq!(reopened["events"][0]["eventType"], "conversation.created");
    assert_eq!(
        reopened["events"][0]["cursor"].as_str().unwrap(),
        acknowledged_cursor
    );

    let new_session_id = reopened["sessionId"].as_str().unwrap();
    let reacknowledged = restarted_client
        .post(url(
            restarted.address,
            &format!("/v1/replay/{new_session_id}/acknowledge"),
        ))
        .header("authorization", &restarted_authorization)
        .json(&json!({"cursor": acknowledged_cursor}))
        .send()
        .await
        .unwrap();
    assert_eq!(reacknowledged.status(), StatusCode::OK);
    drop(reacknowledged);
    drop(restarted_client);
    restarted.stop().await;
}
