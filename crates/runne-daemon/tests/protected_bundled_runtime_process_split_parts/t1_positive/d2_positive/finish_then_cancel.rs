use super::verify;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
    terminal_version: u64,
    read_watch: &std::fs::File,
    create_watch: &std::fs::File,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) {
    let request = runne_runtime_client::CancelTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("d2-finish-before-cancel-{}", uuid::Uuid::now_v7()),
        )
        .expect("late cancellation identity"),
        task,
        terminal_version,
    );
    assert!(client.cancel_task_run(request).await.is_err());
    let after = client
        .get_task_run(task)
        .await
        .expect("read completed TaskRun");
    assert_eq!(after.state(), runne_runtime_client::TaskRunState::Succeeded);
    assert_eq!(after.stream_version(), terminal_version);
    verify::assert_request_counts(runtime_root);
    verify::assert_encrypted_results(database, task, 2);
    assert_eq!(verify::invocation_count(database, task), 2);
    assert_eq!(verify::reserved_effect_count(database, task), 2);
    assert_eq!(verify::release_intent_count(database, task), 2);
    assert_eq!(
        super::super::diagnostic::count_watch_mask(read_watch, libc::IN_OPEN),
        0
    );
    assert_eq!(
        super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
        0
    );
    verify::assert_conversation_receipt(client, conversation, task, database, runtime_root).await;
    eprintln!("PASS: late cancel after D2 finish left the single success receipt unchanged");
}
