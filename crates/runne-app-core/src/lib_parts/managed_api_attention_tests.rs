#[tokio::test]
async fn managed_inventory_and_attention_use_authoritative_terminal_and_approval_state() {
    let submissions = Arc::new(AtomicUsize::new(0));
    let snapshots = json!([
        run_snapshot(TASK_RUN, "reconciling", Some(ATTEMPT), &Value::Null),
        run_snapshot(
            "018f2e3a-7000-7000-8000-000000000911",
            "unrecoverable",
            None,
            &Value::Null
        ),
        run_snapshot(
            "018f2e3a-7000-7000-8000-000000000912",
            "failed",
            None,
            &Value::Null
        ),
        run_snapshot(
            "018f2e3a-7000-7000-8000-000000000913",
            "succeeded",
            None,
            &json!({"type":"success"})
        ),
        run_snapshot(
            "018f2e3a-7000-7000-8000-000000000914",
            "cancelling",
            Some(ATTEMPT),
            &Value::Null
        )
    ]);
    let approval = json!({"approvalId":APPROVAL, "taskRunId":TASK_RUN, "attemptId":ATTEMPT,
        "invocationId":INVOCATION, "action":"fs:write", "resource":"workspace:/src/a.rs",
        "actionDigest":"1111111111111111111111111111111111111111111111111111111111111111",
        "policyRevision":7, "requestVersion":3, "approvalGeneration":4, "expiresAt":2000,
        "riskSummary":"write source", "state":"pending"});
    let origin = managed_api_server(ManagedApiMock {
        submissions,
        task_run_ids: Arc::default(),
        fail_approvals: false,
        task_runs: snapshots,
        approvals: json!([approval]),
    })
    .await;
    let session = mutation_test_client("managed-authority", "managed-lineage", 1)
        .session_info()
        .clone();
    let client = runne_runtime_client::mock_authenticated_runtime_client(&origin, session).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let core =
        AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), client).unwrap();
    let inventory = core.list_managed_task_runs().await.unwrap();
    assert_eq!(inventory.task_runs.len(), 5);
    let attention = core.managed_attention_snapshot().await.unwrap();
    assert!(
        attention
            .items
            .iter()
            .any(|item| item.task_run_id.as_deref() == Some(TASK_RUN) && item.kind == "uncertain")
    );
    assert!(
        attention
            .items
            .iter()
            .any(|item| item.task_run_id.as_deref()
                == Some("018f2e3a-7000-7000-8000-000000000911")
                && item.kind == "uncertain")
    );
    assert!(
        attention
            .items
            .iter()
            .any(|item| item.task_run_id.as_deref()
                == Some("018f2e3a-7000-7000-8000-000000000912")
                && item.kind == "failed")
    );
    assert!(
        attention
            .items
            .iter()
            .any(|item| item.approval_id.as_deref() == Some(APPROVAL) && item.kind == "approval")
    );
    assert!(!attention.items.iter().any(
            |item| item.task_run_id.as_deref() == Some("018f2e3a-7000-7000-8000-000000000913")
        ));
    assert!(!attention.items.iter().any(
            |item| item.task_run_id.as_deref() == Some("018f2e3a-7000-7000-8000-000000000914")
        ));
    assert!(
        attention
            .items
            .iter()
            .any(|item| item.kind == "effective_authority_unavailable")
    );
    assert!(
        attention
            .items
            .iter()
            .any(|item| item.kind == "effects_unavailable")
    );
}

#[tokio::test]
async fn managed_attention_marks_bounded_truncation_incomplete_and_fails_when_approval_source_fails()
 {
    let submissions = Arc::new(AtomicUsize::new(0));
    let approvals = (0..65)
        .map(|index| {
            json!({
                "approvalId":format!("018f2e3a-7000-7000-8000-{index:012x}"),
                "taskRunId":TASK_RUN, "attemptId":null, "invocationId":INVOCATION,
                "action":"fs:write", "resource":"workspace:/src/a.rs",
                "actionDigest":"1111111111111111111111111111111111111111111111111111111111111111",
                "policyRevision":7, "requestVersion":3, "approvalGeneration":4, "expiresAt":2000,
                "riskSummary":"write source", "state":"pending"
            })
        })
        .collect::<Vec<_>>();
    let origin = managed_api_server(ManagedApiMock {
        submissions: submissions.clone(),
        task_run_ids: Arc::default(),
        fail_approvals: false,
        task_runs: json!([]),
        approvals: json!(approvals),
    })
    .await;
    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        mutation_test_client("managed-authority", "managed-lineage", 1)
            .session_info()
            .clone(),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let core =
        AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), client).unwrap();
    let attention = core.managed_attention_snapshot().await.unwrap();
    assert!(!attention.complete);
    assert_eq!(attention.items.len(), 64);

    let failing_origin = managed_api_server(ManagedApiMock {
        submissions,
        task_run_ids: Arc::default(),
        fail_approvals: true,
        task_runs: json!([]),
        approvals: json!([]),
    })
    .await;
    let failing_client = runne_runtime_client::mock_authenticated_runtime_client(
        &failing_origin,
        mutation_test_client("managed-authority-2", "managed-lineage-2", 1)
            .session_info()
            .clone(),
    )
    .unwrap();
    let failing_core = AppCore::open_with_mock_runtime(
        &tempfile::tempdir().unwrap().path().join("profile.sqlite3"),
        failing_client,
    )
    .unwrap();
    assert!(failing_core.managed_attention_snapshot().await.is_err());
}
