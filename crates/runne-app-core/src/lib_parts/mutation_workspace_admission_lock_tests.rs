#[tokio::test]
async fn prepare_admission_mismatch_rejects_without_waiting_for_the_operation_lock() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let directory = tempfile::tempdir().expect("directory");
    let core = std::sync::Arc::new(protected_workspace_core(&origin, &directory).await);
    let (locked, lock_available) = tokio::sync::oneshot::channel::<()>();
    let (release, release_signal) = tokio::sync::oneshot::channel::<()>();
    let holder = {
        let core = std::sync::Arc::clone(&core);
        tokio::spawn(async move {
            let _operation = core.runtime_operation.lock().await;
            locked.send(()).expect("lock acquisition witnessed");
            let _held = release_signal.await;
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), lock_available)
        .await
        .expect("operation lock must be held by the fixture")
        .expect("lock signal");
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        core.prepare_open_selected_workspace(
            WORKSPACE_ID.parse().expect("workspace A"),
            1,
            protected_admission_for(WRONG_ID, 1),
        ),
    )
    .await
    .expect("mismatched admission must reject without waiting for the held lock");
    assert!(matches!(result, Err(AppCoreError::InvalidMutation)));
    assert!(
        !format!("{result:?}").contains(WRONG_ID),
        "rejection must stay redacted"
    );
    release.send(()).expect("release the held lock");
    holder.await.expect("lock holder finishes");
}
