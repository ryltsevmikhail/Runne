#[tokio::test]
async fn prepare_rejects_typed_admission_mismatch_before_any_http_io() {
    for (admission_workspace, admission_version) in [(WRONG_ID, 1), (WORKSPACE_ID, 2)] {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let observer = tokio::spawn(async move {
            match tokio::time::timeout(
                std::time::Duration::from_millis(250),
                listener.accept(),
            )
            .await
            {
                Err(_) => {}
                Ok(Ok(_)) => panic!("early admission validation opened HTTP I/O"),
                Ok(Err(error)) => panic!("zero-I/O observer failed: {error}"),
            }
        });
        let directory = tempfile::tempdir().expect("directory");
        let core = protected_workspace_core(&origin, &directory).await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            core.prepare_open_selected_workspace(
                WORKSPACE_ID.parse().expect("workspace A"),
                1,
                protected_admission_for(admission_workspace, admission_version),
            ),
        )
        .await
        .expect("bounded prepare");

        assert!(
            matches!(result, Err(AppCoreError::InvalidMutation)),
            "mismatched admission for {admission_workspace}/{admission_version}"
        );
        assert!(!format!("{result:?}").contains(WRONG_ID));
        observer.await.expect("bounded zero-I/O observer");
    }
}

#[tokio::test]
async fn early_root_validation_failure_disposition_follows_possible_send() {
    for (possible_send, expected) in [
        (false, NativeAuthorityDisposition::ReapBeforeDispatch),
        (true, NativeAuthorityDisposition::ReleaseWithoutReap),
    ] {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(workspace_server(
            listener,
            vec![WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false))],
            1,
        ));
        let directory = tempfile::tempdir().expect("directory");
        let core = protected_workspace_core(&origin, &directory).await;
        let mut prepared = core
            .prepare_open_selected_workspace(
                WORKSPACE_ID.parse().expect("workspace"),
                1,
                protected_admission_for(WORKSPACE_ID, 1),
            )
            .await
            .expect("prepare");
        prepared.possible_send = possible_send;
        prepared.bind.finalized_root = None;
        let failure = core
            .dispatch_prepared_workspace_open(&mut prepared)
            .await
            .expect_err("invalid early admission must fail closed");
        assert_eq!(failure.disposition(), expected);
        let requests = server.await.expect("server");
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.contains("POST /v1/workspaces/"))
                .count(),
            0
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.contains("/root-bindings"))
                .count(),
            0
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.contains("/open HTTP/1.1"))
                .count(),
            0
        );
    }
}

#[tokio::test]
async fn concurrent_version_race_in_bind_outcome_never_opens_a_successor() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(
        listener,
        vec![
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 3)),
            WorkspaceReply::Json(
                200,
                workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 3),
            ),
        ],
        3,
    ));
    let directory = tempfile::tempdir().expect("directory");
    let core = protected_workspace_core(&origin, &directory).await;
    let mut prepared = core
        .prepare_open_selected_workspace(
            WORKSPACE_ID.parse().expect("workspace"),
            1,
            protected_admission(1),
        )
        .await
        .expect("prepare");
    let failure = core
        .dispatch_prepared_workspace_open(&mut prepared)
        .await
        .expect_err("raced bind version must fail closed");
    assert_eq!(
        failure.disposition(),
        NativeAuthorityDisposition::ReleaseWithoutReap
    );
    assert!(!format!("{failure:?}").contains(WORKSPACE_ID));
    let requests = server.await.expect("server");
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("/root-bindings"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("/open HTTP/1.1"))
            .count(),
        0
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("GET /v1/workspaces/"))
            .count(),
        1
    );
}

#[tokio::test]
async fn wrong_open_outcome_version_never_reaches_the_final_snapshot() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(
        listener,
        vec![
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 2)),
            WorkspaceReply::Json(
                200,
                workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 2),
            ),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 5)),
            WorkspaceReply::Json(
                200,
                workspace_reconcile("open_workspace", WORKSPACE_ID, 5),
            ),
        ],
        5,
    ));
    let directory = tempfile::tempdir().expect("directory");
    let core = protected_workspace_core(&origin, &directory).await;
    let mut prepared = core
        .prepare_open_selected_workspace(
            WORKSPACE_ID.parse().expect("workspace"),
            1,
            protected_admission(1),
        )
        .await
        .expect("prepare");
    let failure = core
        .dispatch_prepared_workspace_open(&mut prepared)
        .await
        .expect_err("wrong open version must fail closed");
    assert_eq!(
        failure.disposition(),
        NativeAuthorityDisposition::ReleaseWithoutReap
    );
    assert!(!format!("{failure:?}").contains(WORKSPACE_ID));
    let requests = server.await.expect("server");
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("/root-bindings"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("/open HTTP/1.1"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("GET /v1/workspaces/"))
            .count(),
        1
    );
}

#[tokio::test]
async fn wrong_operation_outcome_for_the_bind_never_opens_a_successor() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(
        listener,
        vec![
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 2)),
            WorkspaceReply::Json(
                200,
                workspace_reconcile("open_workspace", WORKSPACE_ID, 2),
            ),
        ],
        3,
    ));
    let directory = tempfile::tempdir().expect("directory");
    let core = protected_workspace_core(&origin, &directory).await;
    let mut prepared = core
        .prepare_open_selected_workspace(
            WORKSPACE_ID.parse().expect("workspace"),
            1,
            protected_admission(1),
        )
        .await
        .expect("prepare");
    let failure = core
        .dispatch_prepared_workspace_open(&mut prepared)
        .await
        .expect_err("wrong operation outcome must fail closed");
    assert_eq!(
        failure.disposition(),
        NativeAuthorityDisposition::ReleaseWithoutReap
    );
    assert!(!format!("{failure:?}").contains(WORKSPACE_ID));
    let requests = server.await.expect("server");
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("/root-bindings"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("/open HTTP/1.1"))
            .count(),
        0
    );
}
