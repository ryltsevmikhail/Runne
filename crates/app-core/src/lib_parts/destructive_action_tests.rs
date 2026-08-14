async fn destructive_response(stream: &mut tokio::net::TcpStream, status: &str, body: String) {
    stream.write_all(format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("response");
}

struct AcceptedDestructiveConfirmation;

impl DestructiveConfirmationLease for AcceptedDestructiveConfirmation {
    fn wait_for_consume<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(std::future::ready(true))
    }

    fn try_commit(&mut self) -> bool { true }
}

struct AcceptedDestructivePort;

impl DestructiveConfirmationPort for AcceptedDestructivePort {
    fn confirm(
        &self,
        _: DestructiveConfirmationContext,
    ) -> DestructiveConfirmationFuture<'_> {
        Box::pin(std::future::ready(Some(
            Box::new(AcceptedDestructiveConfirmation) as Box<dyn DestructiveConfirmationLease>,
        )))
    }
}

struct DeniedDestructivePort;

impl DestructiveConfirmationPort for DeniedDestructivePort {
    fn confirm(
        &self,
        _: DestructiveConfirmationContext,
    ) -> DestructiveConfirmationFuture<'_> {
        Box::pin(std::future::ready(None))
    }
}

struct BlockingDestructivePort {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl DestructiveConfirmationPort for BlockingDestructivePort {
    fn confirm(
        &self,
        _: DestructiveConfirmationContext,
    ) -> DestructiveConfirmationFuture<'_> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            None
        })
    }
}

#[tokio::test]
async fn cancellation_during_native_confirmation_closes_the_anchored_action() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000913").expect("project");
    let server = tokio::spawn(async move {
        for body in [
            format!(r#"{{"projectId":"{project}","displayName":"Project","version":1,"archived":false}}"#),
            r#"{"items":[],"nextCursor":null}"#.into(),
            format!(r#"{{"projectId":"{project}","displayName":"Project","version":1,"archived":false}}"#),
            r#"{"items":[],"nextCursor":null}"#.into(),
        ] {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut buffer = [0; 4096];
            let _ = stream.read(&mut buffer).await.expect("read");
            destructive_response(&mut stream, "200 OK", body).await;
        }
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = std::sync::Arc::new(
        AppCore::open_with_mock_runtime(
            &directory.path().join("profile.sqlite3"),
            adversarial_client(&origin),
        )
        .expect("core"),
    );
    let port = std::sync::Arc::new(BlockingDestructivePort {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let task = {
        let core = std::sync::Arc::clone(&core);
        let port = std::sync::Arc::clone(&port);
        tokio::spawn(async move {
            core.execute_destructive_project_action(
                ProjectDestructiveOperation::Archive,
                project,
                1,
                port.as_ref(),
            )
            .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), port.entered.notified())
        .await
        .expect("confirmation entered");
    task.abort();
    let _ = task.await;

    let retry = core
        .prepare_destructive_project_action(ProjectDestructiveOperation::Archive, project, 1)
        .await
        .expect("replay");
    assert_eq!(
        retry.lease.anchored_record.disposition(),
        gocode_local_store::ClientMutationDisposition::ManualResolution
    );
    server.await.expect("server");
}

#[tokio::test]
async fn native_denial_synchronously_closes_the_anchored_action() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000912").expect("project");
    let server = tokio::spawn(async move {
        for body in [
            format!(r#"{{"projectId":"{project}","displayName":"Project","version":1,"archived":false}}"#),
            r#"{"items":[],"nextCursor":null}"#.into(),
            format!(r#"{{"projectId":"{project}","displayName":"Project","version":1,"archived":false}}"#),
            r#"{"items":[],"nextCursor":null}"#.into(),
        ] {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut buffer = [0; 4096];
            let _ = stream.read(&mut buffer).await.expect("read");
            destructive_response(&mut stream, "200 OK", body).await;
        }
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        adversarial_client(&origin),
    )
    .expect("core");

    assert!(matches!(
        core.execute_destructive_project_action(
            ProjectDestructiveOperation::Archive,
            project,
            1,
            &DeniedDestructivePort,
        )
        .await,
        Err(AppCoreError::MutationUnavailable)
    ));
    let retry = core
        .prepare_destructive_project_action(ProjectDestructiveOperation::Archive, project, 1)
        .await
        .expect("replay");
    assert_eq!(
        retry.lease.anchored_record.disposition(),
        gocode_local_store::ClientMutationDisposition::ManualResolution
    );
    server.await.expect("server");
}

async fn destructive_sequence(operation: ProjectDestructiveOperation) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000909").expect("project");
    let operation_name = match operation { ProjectDestructiveOperation::Archive => "archive_project", ProjectDestructiveOperation::Delete => "delete_project" };
    let server = tokio::spawn(async move {
        let (mut get, _) = listener.accept().await.expect("project read");
        let mut buffer = [0; 4096]; let used = get.read(&mut buffer).await.expect("read");
        let get_request = String::from_utf8_lossy(&buffer[..used]).into_owned();
        destructive_response(&mut get, "200 OK", format!(r#"{{"projectId":"{project}","displayName":"Project","version":1,"archived":false}}"#)).await;
        let (mut impacts, _) = listener.accept().await.expect("impact read");
        let used = impacts.read(&mut buffer).await.expect("read");
        let impacts_request = String::from_utf8_lossy(&buffer[..used]).into_owned();
        destructive_response(&mut impacts, "200 OK", r#"{"items":[],"nextCursor":null}"#.into()).await;
        let (mut final_check, _) = listener.accept().await.expect("final project read");
        let used = final_check.read(&mut buffer).await.expect("read");
        let final_check_request = String::from_utf8_lossy(&buffer[..used]).into_owned();
        destructive_response(&mut final_check, "200 OK", format!(r#"{{"projectId":"{project}","displayName":"Project","version":1,"archived":false}}"#)).await;
        let (mut mutation, _) = listener.accept().await.expect("mutation");
        let used = mutation.read(&mut buffer).await.expect("read");
        let mutation_request = String::from_utf8_lossy(&buffer[..used]).into_owned();
        destructive_response(&mut mutation, "202 Accepted", format!(r#"{{"projectId":"{project}","newVersion":2}}"#)).await;
        let (mut reconcile, _) = listener.accept().await.expect("reconcile");
        let used = reconcile.read(&mut buffer).await.expect("read");
        let reconcile_request = String::from_utf8_lossy(&buffer[..used]).into_owned();
        destructive_response(&mut reconcile, "200 OK", format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"{operation_name}","projectId":"{project}","newVersion":2}}}}"#)).await;
        (get_request, impacts_request, final_check_request, mutation_request, reconcile_request)
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), adversarial_client(&origin)).expect("core");
    assert_eq!(
        core.execute_destructive_project_action(operation, project, 1, &AcceptedDestructivePort)
            .await
            .expect("dispatch")
            .new_version(),
        2
    );
    let (get, impacts, final_check, mutation, reconcile) = server.await.expect("server");
    assert!(get.starts_with(&format!("GET /v1/projects/{project} HTTP/1.1")));
    assert!(impacts.starts_with(&format!("GET /v1/projects/{project}/workspaces?limit=100 HTTP/1.1")));
    assert!(final_check.starts_with(&format!("GET /v1/projects/{project} HTTP/1.1")));
    match operation {
        ProjectDestructiveOperation::Archive => assert!(mutation.starts_with(&format!("POST /v1/projects/{project}/archive HTTP/1.1"))),
        ProjectDestructiveOperation::Delete => assert!(mutation.starts_with(&format!("DELETE /v1/projects/{project} HTTP/1.1"))),
    }
    assert!(reconcile.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}

#[tokio::test]
async fn archive_runs_the_full_protected_sequence() { destructive_sequence(ProjectDestructiveOperation::Archive).await; }

#[tokio::test]
async fn delete_runs_the_full_protected_sequence() { destructive_sequence(ProjectDestructiveOperation::Delete).await; }

#[tokio::test]
async fn post_confirmation_runtime_revocation_fences_before_mutation() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000910").expect("project");
    let server = tokio::spawn(async move {
        for body in [format!(r#"{{"projectId":"{project}","displayName":"Project","version":1,"archived":false}}"#), r#"{"items":[],"nextCursor":null}"#.into()] {
            let (mut stream, _) = listener.accept().await.expect("read"); let mut buffer = [0; 4096]; let _ = stream.read(&mut buffer).await.expect("request"); destructive_response(&mut stream, "200 OK", body).await;
        }
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), adversarial_client(&origin)).expect("core");
    let action = core
        .prepare_destructive_project_action(ProjectDestructiveOperation::Archive, project, 1)
        .await
        .expect("prepared");
    let mut guard = PreparedDestructiveActionGuard::new(&core, action);
    core.set_runtime_availability(RuntimeAvailability::Reconnecting).expect("revoke");
    let mut confirmation = AcceptedDestructiveConfirmation;
    assert!(matches!(
        core.dispatch_destructive_project_action(&mut guard, &mut confirmation).await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    server.await.expect("server");
}

#[tokio::test]
async fn anchor_failure_blocks_destructive_confirmation_before_any_mutation() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000911").expect("project");
    let server = tokio::spawn(async move {
        for body in [format!(r#"{{"projectId":"{project}","displayName":"Project","version":1,"archived":false}}"#), r#"{"items":[],"nextCursor":null}"#.into()] {
            let (mut stream, _) = listener.accept().await.expect("read"); let mut buffer = [0; 4096]; let _ = stream.read(&mut buffer).await.expect("request"); destructive_response(&mut stream, "200 OK", body).await;
        }
    });
    let profile = [0x61; 32];
    let secure = std::sync::Arc::new(gocode_secure_store::test_support::DeterministicSecureStore::new(profile));
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_test_runtime_secure(&directory.path().join("profile.sqlite3"), adversarial_client(&origin), secure.clone(), profile).expect("core");
    secure.fail_next_advance();
    assert!(matches!(core.prepare_destructive_project_action(ProjectDestructiveOperation::Delete, project, 1).await, Err(AppCoreError::MutationUnavailable)));
    server.await.expect("server");
}
