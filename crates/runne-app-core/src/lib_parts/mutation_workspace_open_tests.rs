#[tokio::test]
async fn open_workspace_rebinds_root_without_an_open_successor() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(
        listener,
        vec![
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 2, true)),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 3)),
            WorkspaceReply::Json(
                200,
                workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 3),
            ),
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 3, true)),
        ],
        4,
    ));
    let directory = tempfile::tempdir().expect("directory");
    let core = protected_workspace_core(&origin, &directory).await;
    let mut prepared = core
        .prepare_open_selected_workspace(
            WORKSPACE_ID.parse().expect("workspace"),
            2,
            protected_admission(2),
        )
        .await
        .expect("prepare");

    let snapshot = core
        .dispatch_prepared_workspace_open(&mut prepared)
        .await
        .expect("rebind");
    assert_eq!(snapshot.id().to_string(), WORKSPACE_ID);
    assert_eq!(snapshot.version(), 3);
    assert!(snapshot.is_open());
    let requests = server.await.expect("server");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("/root-bindings"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("/open HTTP/1.1"))
            .count(),
        0
    );
}

#[tokio::test]
async fn open_workspace_rebind_rejects_a_stale_final_snapshot() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(
        listener,
        vec![
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 2, true)),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 3)),
            WorkspaceReply::Json(
                200,
                workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 3),
            ),
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 2, true)),
        ],
        4,
    ));
    let directory = tempfile::tempdir().expect("directory");
    let core = protected_workspace_core(&origin, &directory).await;
    let mut prepared = core
        .prepare_open_selected_workspace(
            WORKSPACE_ID.parse().expect("workspace"),
            2,
            protected_admission(2),
        )
        .await
        .expect("prepare");

    let failure = core
        .dispatch_prepared_workspace_open(&mut prepared)
        .await
        .expect_err("stale final snapshot");
    assert_eq!(
        failure.disposition(),
        NativeAuthorityDisposition::ReleaseWithoutReap
    );
    server.await.expect("server");
}

#[tokio::test]
async fn open_workspace_rebind_retry_does_not_synthesize_an_open() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(
        listener,
        vec![
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 2, true)),
            WorkspaceReply::Close,
            WorkspaceReply::Json(200, r#"{"disposition":"indeterminate"}"#.into()),
            WorkspaceReply::Json(
                200,
                workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 3),
            ),
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 3, true)),
        ],
        5,
    ));
    let directory = tempfile::tempdir().expect("directory");
    let core = protected_workspace_core(&origin, &directory).await;
    let mut prepared = core
        .prepare_open_selected_workspace(
            WORKSPACE_ID.parse().expect("workspace"),
            2,
            protected_admission(2),
        )
        .await
        .expect("prepare");

    assert_eq!(
        core.dispatch_prepared_workspace_open(&mut prepared)
            .await
            .expect_err("indeterminate bind")
            .disposition(),
        NativeAuthorityDisposition::ReleaseWithoutReap,
    );
    assert!(
        core.dispatch_prepared_workspace_open(&mut prepared)
            .await
            .is_ok()
    );
    let requests = server.await.expect("server");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("/root-bindings"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("/open HTTP/1.1"))
            .count(),
        0
    );
}

#[tokio::test]
async fn closed_workspace_reconciles_a_lost_open_ack_without_a_second_post() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
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
            WorkspaceReply::Close,
            WorkspaceReply::Json(200, r#"{"disposition":"indeterminate"}"#.into()),
            WorkspaceReply::Json(
                200,
                workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 2),
            ),
            WorkspaceReply::Json(200, workspace_reconcile("open_workspace", WORKSPACE_ID, 3)),
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 3, true)),
        ],
        8,
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

    assert_eq!(
        core.dispatch_prepared_workspace_open(&mut prepared)
            .await
            .expect_err("lost open acknowledgement")
            .disposition(),
        NativeAuthorityDisposition::ReleaseWithoutReap,
    );
    let snapshot = core
        .dispatch_prepared_workspace_open(&mut prepared)
        .await
        .expect("reconciled open");
    assert_eq!(snapshot.version(), 3);
    assert!(snapshot.is_open());
    let requests = server.await.expect("server");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("/root-bindings"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("/open HTTP/1.1"))
            .count(),
        1
    );
}

#[tokio::test]
async fn closed_workspace_refreshes_the_unstarted_open_gate_after_rotation() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(
        listener,
        vec![WorkspaceReply::Json(
            200,
            workspace_snapshot(WORKSPACE_ID, 1, false),
        )],
        1,
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
    let next_epoch = core
        .mutation_gate_epoch
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
        .checked_add(1)
        .expect("epoch");
    let (bind, open, _) = prepared.parts_and_possible_send_mut();
    let open = open.expect("closed workspace has an open successor");

    core.admit_unstarted_composite_successor(bind, open)
        .expect("re-admit open");
    assert_ne!(bind.gate_epoch, open.gate_epoch);
    assert_eq!(open.gate_epoch, next_epoch);
    server.await.expect("server");
}
