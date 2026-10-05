#[derive(Clone)]
struct AttentionEffectsMock {
    task_runs: Value,
    effects: std::collections::HashMap<String, Value>,
    effect_reads: Arc<AtomicUsize>,
    mutations: Arc<AtomicUsize>,
}

async fn attention_effects_server(mock: AttentionEffectsMock) -> String {
    let router = Router::new()
        .fallback(any(attention_effects_request))
        .with_state(mock);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{address}")
}

async fn attention_effects_request(
    State(mock): State<AttentionEffectsMock>,
    request: Request<Body>,
) -> Response<Body> {
    let path = request.uri().path().to_owned();
    if request.method() != Method::GET {
        mock.mutations.fetch_add(1, Ordering::SeqCst);
    }
    match (request.method(), path.as_str()) {
        (&Method::GET, "/v1/task-runs") => {
            json_response(StatusCode::OK, &json!({"taskRuns":mock.task_runs}))
        }
        (&Method::GET, "/v1/approvals") => {
            json_response(StatusCode::OK, &json!({"items":[]}))
        }
        (&Method::GET, p) if p.starts_with("/v1/task-runs/") && p.ends_with("/effects") => {
            mock.effect_reads.fetch_add(1, Ordering::SeqCst);
            let id = p.trim_start_matches("/v1/task-runs/").trim_end_matches("/effects");
            mock.effects.get(id).map_or_else(
                || json_response(StatusCode::NOT_FOUND, &json!({"code":"not_found"})),
                |value| json_response(StatusCode::OK, value),
            )
        }
        _ => json_response(StatusCode::NOT_FOUND, &json!({"code":"not_found"})),
    }
}

fn attention_effects_wire(
    id: &str,
    stream_version: u64,
    attempt_id: Option<&str>,
    local_command: &Value,
    remote: &Value,
) -> Value {
    json!({
        "taskRunId":id,
        "streamVersion":stream_version,
        "attemptId":attempt_id,
        "cancellationRequested":true,
        "localCommand":local_command,
        "remote":remote,
        "successor":"blocked"
    })
}

fn known_running_effects() -> Value {
    json!({
        "outcome":"running", "publication":"allowed", "accounting":"known",
        "cancellation":"requested", "availability":"available",
        "capabilities":{"statusCheck":true,"streamResume":false,"remoteCancel":true},
        "usageKnown":true
    })
}

fn unknown_remote_effects() -> Value {
    json!({
        "outcome":"unknown", "publication":"unknown", "accounting":"unknown",
        "cancellation":"requested", "availability":"unavailable",
        "capabilities":{"statusCheck":true,"streamResume":false,"remoteCancel":true},
        "usageKnown":null
    })
}

async fn effects_test_core(
    task_runs: Value,
    effects: std::collections::HashMap<String, Value>,
    effect_reads: Arc<AtomicUsize>,
    mutations: Arc<AtomicUsize>,
) -> AppCore {
    let origin = attention_effects_server(AttentionEffectsMock {
        task_runs,
        effects,
        effect_reads,
        mutations,
    })
    .await;
    let session = mutation_test_client("effects-authority", "effects-lineage", 1)
        .session_info()
        .clone();
    let client = runne_runtime_client::mock_authenticated_runtime_client(&origin, session).unwrap();
    AppCore::open_with_mock_runtime(
        &tempfile::tempdir().unwrap().path().join("effects.sqlite3"),
        client,
    )
    .unwrap()
}

#[tokio::test]
async fn attention_uses_typed_effects_and_keeps_requested_cancel_distinct() {
    const UNKNOWN_LOCAL: &str = "018f2e3a-7000-7000-8000-000000000921";
    const REQUESTED_CANCEL: &str = "018f2e3a-7000-7000-8000-000000000922";
    let task_runs = json!([
        run_snapshot(TASK_RUN, "succeeded", None, &json!({"type":"success"})),
        run_snapshot(UNKNOWN_LOCAL, "reconciling", Some(ATTEMPT), &Value::Null),
        run_snapshot(REQUESTED_CANCEL, "cancelling", Some(ATTEMPT), &Value::Null)
    ]);
    let effects = std::collections::HashMap::from([
        (
            TASK_RUN.to_owned(),
            attention_effects_wire(
                TASK_RUN,
                4,
                Some(ATTEMPT),
                &Value::Null,
                &unknown_remote_effects(),
            ),
        ),
        (
            UNKNOWN_LOCAL.to_owned(),
            attention_effects_wire(
                UNKNOWN_LOCAL,
                4,
                Some(ATTEMPT),
                &json!({"outcome":"outcome_unknown","stop":"unconfirmed","exitCode":null}),
                &known_running_effects(),
            ),
        ),
        (
            REQUESTED_CANCEL.to_owned(),
            attention_effects_wire(
                REQUESTED_CANCEL,
                4,
                Some(ATTEMPT),
                &Value::Null,
                &known_running_effects(),
            ),
        ),
    ]);
    let effect_reads = Arc::new(AtomicUsize::new(0));
    let mutations = Arc::new(AtomicUsize::new(0));
    let core = effects_test_core(
        task_runs,
        effects,
        effect_reads.clone(),
        mutations.clone(),
    )
    .await;

    let attention = core.managed_attention_snapshot().await.unwrap();
    assert!(attention.complete);
    assert_eq!(effect_reads.load(Ordering::SeqCst), 3);
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
    assert!(attention.items.iter().any(|item| {
        item.task_run_id.as_deref() == Some(TASK_RUN)
            && item.kind == "uncertain"
            && item.workspace_id.as_deref() == Some(WORKSPACE)
            && item.conversation_id.as_deref() == Some(CONVERSATION)
    }));
    assert!(attention.items.iter().any(|item| {
        item.task_run_id.as_deref() == Some(UNKNOWN_LOCAL) && item.kind == "uncertain"
    }));
    assert!(!attention.items.iter().any(|item| {
        item.task_run_id.as_deref() == Some(REQUESTED_CANCEL) && item.kind == "uncertain"
    }));
    assert!(!attention.items.iter().any(|item| item.kind == "effects_unavailable"));
}

#[tokio::test]
async fn stale_or_unavailable_effect_reads_make_attention_incomplete() {
    const STALE_EFFECTS: &str = "018f2e3a-7000-7000-8000-000000000923";
    const MISSING_EFFECTS: &str = "018f2e3a-7000-7000-8000-000000000924";
    let task_runs = json!([
        run_snapshot(STALE_EFFECTS, "succeeded", None, &json!({"type":"success"})),
        run_snapshot(MISSING_EFFECTS, "succeeded", None, &json!({"type":"success"}))
    ]);
    let effects = std::collections::HashMap::from([(
        STALE_EFFECTS.to_owned(),
        attention_effects_wire(
            STALE_EFFECTS,
            3,
            None,
            &Value::Null,
            &known_running_effects(),
        ),
    )]);
    let effect_reads = Arc::new(AtomicUsize::new(0));
    let mutations = Arc::new(AtomicUsize::new(0));
    let core = effects_test_core(
        task_runs,
        effects,
        effect_reads.clone(),
        mutations.clone(),
    )
    .await;

    let attention = core.managed_attention_snapshot().await.unwrap();
    assert!(!attention.complete);
    assert_eq!(effect_reads.load(Ordering::SeqCst), 2);
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
    assert!(attention.items.iter().any(|item| item.kind == "effects_unavailable"));
}

#[tokio::test]
async fn effect_coverage_is_bounded_to_sixty_four_reads() {
    let task_runs = (0..65)
        .map(|index| {
            let id = format!("018f2e3a-7000-7000-8000-{index:012x}");
            run_snapshot(&id, "succeeded", None, &json!({"type":"success"}))
        })
        .collect::<Vec<_>>();
    let effect_reads = Arc::new(AtomicUsize::new(0));
    let mutations = Arc::new(AtomicUsize::new(0));
    let core = effects_test_core(
        json!(task_runs),
        std::collections::HashMap::<String, Value>::default(),
        effect_reads.clone(),
        mutations.clone(),
    )
    .await;

    let attention = core.managed_attention_snapshot().await.unwrap();
    assert!(!attention.complete);
    assert_eq!(effect_reads.load(Ordering::SeqCst), 64);
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
    assert!(attention.items.iter().any(|item| item.kind == "effects_unavailable"));
}
