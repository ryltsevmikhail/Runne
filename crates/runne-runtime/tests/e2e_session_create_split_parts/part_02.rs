#[tokio::test]
async fn pending_binding_recovers_after_host_commit_before_binding_commit() {
    let (runtime_fixture, runtime_store) = RuntimeFixture::new("session-create-recovery");
    let binding_directory = tempfile::tempdir().unwrap();
    let binding_path = binding_directory.path().join("binding.sqlite");

    let binding = SqliteSessionBindingStore::open(&binding_path).unwrap();
    let failing_host = FailAfterDurableHost {
        inner: open_host(runtime_store),
    };
    let failing_service =
        OpenCodeSessionCreateService::new(binding.clone(), failing_host, profile(), schema());
    let first = failing_service
        .create_session(key(), &request(), wire_input())
        .await;
    assert!(matches!(
        first,
        Err(SessionCreateError::Host(HostError::StorageFailure))
    ));
    assert!(matches!(
        binding.lookup(&key()).unwrap(),
        Some(SessionBindingStatus::Pending { .. })
    ));
    drop(failing_service);
    drop(binding);

    let reopened_binding = SqliteSessionBindingStore::open(&binding_path).unwrap();
    let recovered_service = OpenCodeSessionCreateService::new(
        reopened_binding.clone(),
        open_host(runtime_fixture.reopen_store()),
        profile(),
        schema(),
    );
    let response = recovered_service.recover_pending(key()).await.unwrap();
    let retry = recovered_service
        .create_session(key(), &request(), wire_input())
        .await
        .unwrap();
    assert_eq!(response, retry);
    assert!(matches!(
        reopened_binding.lookup(&key()).unwrap(),
        Some(SessionBindingStatus::Committed { .. })
    ));

    let runtime = runtime_fixture.reopen_store();
    assert_eq!(
        runtime
            .load_conversation(CONVERSATION_ID.parse().unwrap())
            .unwrap()
            .events
            .len(),
        1
    );

    drop(runtime);
    drop(recovered_service);
    drop(reopened_binding);
}

#[test]
fn concurrent_retries_commit_one_binding_conversation_event_and_receipt() {
    let (runtime_fixture, runtime_store) = RuntimeFixture::new("session-create-concurrent");
    let binding_directory = tempfile::tempdir().unwrap();
    let binding_path = binding_directory.path().join("binding.sqlite");
    let first_binding = SqliteSessionBindingStore::open(&binding_path).unwrap();
    let second_binding = SqliteSessionBindingStore::open(&binding_path).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let first_store = runtime_store.clone();
    let first_barrier = barrier.clone();
    let first = std::thread::spawn(move || {
        let service_one = OpenCodeSessionCreateService::new(
            first_binding,
            BarrierHost {
                inner: open_host(first_store),
                barrier: first_barrier,
            },
            profile(),
            schema(),
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(service_one.create_session(key(), &request(), wire_input()))
    });
    let second = std::thread::spawn(move || {
        let service_two = OpenCodeSessionCreateService::new(
            second_binding,
            BarrierHost {
                inner: open_host(runtime_store),
                barrier,
            },
            profile(),
            schema(),
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(service_two.create_session(key(), &request(), wire_input()))
    });
    let first = first.join().unwrap().unwrap();
    let second = second.join().unwrap().unwrap();
    assert_eq!(first, second);

    let runtime_conn = validated_reopen::open_validated_connection(
        &runtime_fixture.database_path,
        runtime_fixture.identity,
    )
    .unwrap();
    let runtime_counts: (i64, i64) = runtime_conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM events WHERE aggregate_type = 2),
                (SELECT COUNT(*) FROM command_receipts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(runtime_counts, (1, 1));
    let binding_conn =
        runne_opencode_adapter_sqlite::schema::open_with_pragmas(&binding_path).unwrap();
    let binding_count: i64 = binding_conn
        .query_row(
            "SELECT COUNT(*) FROM session_bindings WHERE status = 'committed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(binding_count, 1);

    drop(binding_conn);
    drop(runtime_conn);
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_writer_contention_does_not_block_unrelated_tokio_timers() {
    let (runtime_fixture, runtime_store) = RuntimeFixture::new("session-create-async-contention");
    let host = open_host(runtime_store);
    let lock_barrier = Arc::new(Barrier::new(2));
    let lock_thread_barrier = lock_barrier.clone();
    let lock_path = runtime_fixture.database_path.clone();
    let identity = runtime_fixture.identity;
    let (release_lock, await_release) = std::sync::mpsc::channel();
    let lock_thread = std::thread::spawn(move || {
        let conn = validated_reopen::open_validated_connection(&lock_path, identity).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        lock_thread_barrier.wait();
        await_release
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("Tokio worker did not make progress while SQLite was locked");
        conn.execute_batch("ROLLBACK").unwrap();
    });
    lock_barrier.wait();

    let context = request().api_context;
    let input = CreateConversationInput {
        conversation_id: CONVERSATION_ID.parse().unwrap(),
        workspace_id: WORKSPACE_ID.parse().unwrap(),
        command_id: COMMAND_ID.parse().unwrap(),
        idempotency_key: IdempotencyKey::new("async-contention").unwrap(),
    };
    let host_call = tokio::spawn(async move { host.create_conversation(&context, input).await });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(
        !host_call.is_finished(),
        "SQLite contention blocked the current Tokio worker"
    );
    release_lock.send(()).unwrap();

    host_call.await.unwrap().unwrap();
    lock_thread.join().unwrap();
}
