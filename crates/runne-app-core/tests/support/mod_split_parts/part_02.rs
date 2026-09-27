async fn create_conversation(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> (StatusCode, axum::Json<Value>) {
    state.create_count.fetch_add(1, Ordering::SeqCst);
    let conversation_id = body["conversationId"].as_str().expect("conversation ID");
    let workspace_id = body["workspaceId"].as_str().expect("workspace ID");
    let mut inner = state.inner.lock().expect("mock state");
    if inner.conversation_id.as_deref() != Some(conversation_id) {
        inner.events.clear();
        inner.live_senders.clear();
    }
    if inner.events.is_empty() {
        inner.events.push(event(
            conversation_id,
            1,
            "conversation.created",
            &json!({"type": "conversation.created", "workspaceId": workspace_id}),
        ));
    }
    inner.conversation_id = Some(conversation_id.to_owned());
    inner.workspace_id = Some(workspace_id.to_owned());
    drop(inner);
    (
        StatusCode::ACCEPTED,
        axum::Json(json!({
            "conversationId": conversation_id,
            "workspaceId": workspace_id,
            "streamVersion": 1,
            "committedAt": 1
        })),
    )
}

async fn generate_text(
    State(state): State<Arc<MockState>>,
    Path(conversation_id): Path<String>,
    axum::Json(body): axum::Json<Value>,
) -> axum::Json<Value> {
    let count = state.generate_count.fetch_add(1, Ordering::SeqCst) + 1;
    state.generate_changed.notify_waiters();
    if state.block_generate.load(Ordering::SeqCst) {
        state.release_generate.notified().await;
    }
    let text = body["text"].as_str().expect("text").to_owned();
    let task_run_id = "018f2e3a-7000-7000-8000-000000000130";
    let attempt_id = "018f2e3a-7000-7000-8000-000000000131";
    let user_message_id = format!("018f2e3a-7000-7000-8000-{count:012x}");
    let assistant_message_id = format!("018f2e3a-7000-7000-8001-{count:012x}");
    let mut inner = state.inner.lock().expect("mock state");
    let user_sequence = u64::try_from(inner.events.len() + 1).expect("sequence");
    let user = event(
        &conversation_id,
        user_sequence,
        "conversation.message.appended",
        &json!({
            "type": "conversation.message.appended",
            "role": "user",
            "messageId": user_message_id,
            "taskRunId": task_run_id,
            "attemptId": attempt_id,
            "text": text
        }),
    );
    inner.events.push(user.clone());
    broadcast(&mut inner.live_senders, &user, user_sequence);
    let assistant_sequence = user_sequence + 1;
    let assistant_text = format!("mock response: {text}");
    let assistant = event(
        &conversation_id,
        assistant_sequence,
        "conversation.message.appended",
        &json!({
            "type": "conversation.message.appended",
            "role": "assistant",
            "messageId": assistant_message_id,
            "taskRunId": task_run_id,
            "attemptId": attempt_id,
            "text": assistant_text
        }),
    );
    inner.events.push(assistant.clone());
    broadcast(&mut inner.live_senders, &assistant, assistant_sequence);
    drop(inner);
    axum::Json(json!({
        "conversationId": conversation_id,
        "taskRunId": task_run_id,
        "attemptId": attempt_id,
        "conversationStreamVersion": assistant_sequence,
        "taskRunStreamVersion": 1,
        "userMessage": {
            "messageId": user_message_id,
            "role": "user",
            "taskRunId": task_run_id,
            "attemptId": attempt_id,
            "text": text,
            "committedAt": 2
        },
        "assistantMessage": {
            "messageId": assistant_message_id,
            "role": "assistant",
            "taskRunId": task_run_id,
            "attemptId": attempt_id,
            "text": assistant_text,
            "committedAt": 3
        }
    }))
}

async fn open_session(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response<Body> {
    state.open_count.fetch_add(1, Ordering::SeqCst);
    state.open_changed.notify_waiters();
    if state.block_open_session.load(Ordering::SeqCst) {
        state.release_open_session.notified().await;
    }
    if state
        .reconnectable_open_failure_once
        .swap(false, Ordering::SeqCst)
    {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "code": "runtime_unavailable",
                    "requestId": "018f2e3a-7000-7000-8000-000000000191"
                }))
                .expect("unavailable JSON"),
            ))
            .expect("unavailable response");
    }
    if body.get("fromCursor").is_some_and(|value| !value.is_null())
        && state.retention_v2_gap_once.swap(false, Ordering::SeqCst)
    {
        return retention_v2_response(&state, body["aggregateType"].as_str());
    }
    if body.get("fromCursor").is_some_and(|value| !value.is_null())
        && state.retention_gap_once.swap(false, Ordering::SeqCst)
    {
        return Response::builder()
            .status(StatusCode::GONE)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "code": "replay_retention_gap",
                    "requestId": "018f2e3a-7000-7000-8000-000000000190"
                }))
                .expect("retention JSON"),
            ))
            .expect("retention response");
    }
    let events = if body["aggregateType"].as_str() == Some("taskRun") {
        Vec::new()
    } else {
        let inner = state.inner.lock().expect("mock state");
        let start = body
            .get("fromCursor")
            .and_then(Value::as_str)
            .and_then(|cursor| {
                inner
                    .events
                    .iter()
                    .position(|event| event_cursor(event) == cursor)
            })
            .unwrap_or(0);
        inner.events[start..]
            .iter()
            .cloned()
            .map(|mut event| {
                let cursor = event_cursor(&event);
                event
                    .as_object_mut()
                    .expect("event object")
                    .insert("cursor".to_owned(), Value::String(cursor));
                event
            })
            .collect::<Vec<_>>()
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "sessionId": SESSION_ID,
                "highWaterRef": "aa",
                "events": events,
                "hasMore": false
            }))
            .expect("open JSON"),
        ))
        .expect("open response")
}

async fn acknowledge(
    State(state): State<Arc<MockState>>,
    Path(_session_id): Path<String>,
) -> axum::Json<Value> {
    state.ack_count.fetch_add(1, Ordering::SeqCst);
    axum::Json(json!({"acknowledged": true}))
}

async fn complete_catch_up(Path(_session_id): Path<String>) -> axum::Json<Value> {
    axum::Json(json!({
        "catchUpProof": "aa",
        "sessionState": "catch_up_complete"
    }))
}

async fn continue_live(
    State(state): State<Arc<MockState>>,
    Path(_session_id): Path<String>,
) -> axum::Json<Value> {
    let live_delivery_id = if state.bad_live_id_once.swap(false, Ordering::SeqCst) {
        "not-a-uuid"
    } else {
        LIVE_DELIVERY_ID
    };
    axum::Json(json!({
        "liveDeliveryId": live_delivery_id,
        "sessionState": "live"
    }))
}

async fn close_session(
    State(state): State<Arc<MockState>>,
    Path(_session_id): Path<String>,
) -> axum::Json<Value> {
    state.close_count.fetch_add(1, Ordering::SeqCst);
    state.close_changed.notify_waiters();
    axum::Json(json!({"closed": true}))
}

async fn live_events(
    State(state): State<Arc<MockState>>,
    Path(_session_id): Path<String>,
) -> Response<Body> {
    let (sender, receiver) = mpsc::unbounded_channel();
    state
        .inner
        .lock()
        .expect("mock state")
        .live_senders
        .push((sender, 1));
    state.live_count.fetch_add(1, Ordering::SeqCst);
    state.live_changed.notify_waiters();
    let stream = UnboundedReceiverStream::new(receiver).map(Ok::<Bytes, Infallible>);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(stream))
        .expect("SSE response")
}

fn event(conversation_id: &str, sequence: u64, event_type: &str, payload: &Value) -> Value {
    json!({
        "eventId": format!("018f2e3a-7000-7000-8002-{sequence:012x}"),
        "aggregateType": "conversation",
        "aggregateId": conversation_id,
        "sequence": sequence,
        "timestampUnixMicros": 1_722_330_000_000_000_i64 + i64::try_from(sequence).unwrap(),
        "sensitivity": "sensitive",
        "schemaVersion": 1,
        "eventType": event_type,
        "causationEventId": null,
        "integrityDigest": "11".repeat(32),
        "correlationId": conversation_id,
        "correlationType": "conversation",
        "payload": payload,
        "replayBindingId": "018f2e3a700070008000000000000121"
    })
}

fn event_cursor(event: &Value) -> String {
    let sequence = event["sequence"].as_u64().expect("sequence");
    let aggregate = event["aggregateId"].as_str().expect("aggregate id");
    let id = uuid::Uuid::parse_str(aggregate)
        .expect("aggregate UUID")
        .into_bytes();
    let bytes = serde_json::to_vec(&json!({
        "scope":{"Aggregate":{"aggregate_id":id,"aggregate_type":2}},
        "event_id":event["eventId"],"sequence":sequence,"global_position":sequence,
    }))
    .expect("cursor JSON");
    format!("gocode-replay-cursor-v1.{}", hex::encode(bytes))
}
