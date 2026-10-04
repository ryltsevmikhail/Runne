#[derive(Clone, Copy)]
enum NetworkMutationCase {
    CreateProject,
    ArchiveProject,
    RenameProject,
    DeleteProject,
    CreateWorkspace,
    OpenWorkspace,
    CreateConversation,
    GenerateCompleted,
    GenerateRejected,
    GenerateProhibited,
}

impl NetworkMutationCase {
    fn request(self, project: CanonicalId, workspace: CanonicalId, conversation: CanonicalId) -> MutationRequest {
        match self {
            Self::CreateProject => MutationRequest::create_project(project, "Project".into()),
            Self::RenameProject => MutationRequest::rename_project(project, 1, "Renamed".into()),
            Self::ArchiveProject => MutationRequest::archive_project(project, 1),
            Self::DeleteProject => MutationRequest::delete_project(project, 1),
            Self::CreateWorkspace => MutationRequest::create_workspace(project, workspace, "Workspace".into()),
            Self::OpenWorkspace => MutationRequest::open_workspace(workspace, 1),
            Self::CreateConversation => MutationRequest::create_conversation(conversation, workspace),
            Self::GenerateCompleted | Self::GenerateRejected | Self::GenerateProhibited => {
                let command_id = CanonicalId::now_v7();
                let identity = CommandIdentity::new(command_id, command_id.to_string())
                    .expect("identity");
                let target = MutationTarget::try_new(
                    runne_local_store::MutationOperation::ConversationGenerateText,
                    runne_local_store::MutationTargetKind::Conversation,
                    runne_local_store::BoundedCanonicalId::parse(conversation.to_string().as_bytes()).expect("target id"),
                ).expect("target");
                Ok(MutationRequest::for_conversation(
                    runne_local_store::MutationOperation::ConversationGenerateText,
                    target, 1, CanonicalMutationCommand::GenerateText { conversation_id: conversation, text: "hello".into() },
                    identity, command_id.to_string(),
                ))
            }
        }.expect("request")
    }

    fn wire(self, project: CanonicalId, workspace: CanonicalId, conversation: CanonicalId) -> (String, u16, String, String) {
        let generation = |terminal: &str| {
            let task = "018f2e3a-7000-7000-8000-000000000914";
            let attempt = "018f2e3a-7000-7000-8000-000000000915";
            let user = "018f2e3a-7000-7000-8000-000000000916";
            let assistant = "018f2e3a-7000-7000-8000-000000000917";
            let value = format!(r#"{{"conversationId":"{conversation}","taskRunId":"{task}","attemptId":"{attempt}","conversationStreamVersion":3,"taskRunStreamVersion":5,"userMessage":{{"messageId":"{user}","role":"user","taskRunId":"{task}","attemptId":"{attempt}","text":"hello","committedAt":1}},"assistantMessage":{{"messageId":"{assistant}","role":"assistant","taskRunId":"{task}","attemptId":"{attempt}","text":"ack-only","committedAt":2}}}}"#);
            let tail = if terminal == "completed" {
                format!(r#","assistantMessage":{{"messageId":"{assistant}","role":"assistant","taskRunId":"{task}","attemptId":"{attempt}","text":"answer","committedAt":2}}"#)
            } else {
                format!(r#","reservedAssistantMessageId":"{assistant}","reason":"provider_output_rejected""#)
            };
            let durable = format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"generate_conversation_text","terminal":"{terminal}","conversationId":"{conversation}","taskRunId":"{task}","attemptId":"{attempt}","conversationStreamVersion":3,"taskRunStreamVersion":5,"userMessage":{{"messageId":"{user}","role":"user","taskRunId":"{task}","attemptId":"{attempt}","text":"hello","committedAt":1}}{tail}}}}}"#);
            (value, durable)
        };
        match self {
            Self::CreateProject => ("POST /v1/projects HTTP/1.1".into(), 202, format!(r#"{{"projectId":"{project}","newVersion":1}}"#), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{project}","newVersion":1}}}}"#)),
            Self::RenameProject => (format!("POST /v1/projects/{project}/rename HTTP/1.1"), 202, format!(r#"{{"projectId":"{project}","newVersion":2}}"#), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"rename_project","projectId":"{project}","newVersion":2}}}}"#)),
            Self::ArchiveProject => (format!("POST /v1/projects/{project}/archive HTTP/1.1"), 202, format!(r#"{{"projectId":"{project}","newVersion":2}}"#), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"archive_project","projectId":"{project}","newVersion":2}}}}"#)),
            Self::DeleteProject => (format!("DELETE /v1/projects/{project} HTTP/1.1"), 202, format!(r#"{{"projectId":"{project}","newVersion":2}}"#), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"delete_project","projectId":"{project}","newVersion":2}}}}"#)),
            Self::CreateWorkspace => (format!("POST /v1/projects/{project}/workspaces HTTP/1.1"), 202, format!(r#"{{"workspaceId":"{workspace}","newVersion":1}}"#), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_workspace","workspaceId":"{workspace}","newVersion":1}}}}"#)),
            Self::OpenWorkspace => (format!("POST /v1/workspaces/{workspace}/open HTTP/1.1"), 202, format!(r#"{{"workspaceId":"{workspace}","newVersion":2}}"#), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"open_workspace","workspaceId":"{workspace}","newVersion":2}}}}"#)),
            Self::CreateConversation => ("POST /v1/conversations HTTP/1.1".into(), 202, format!(r#"{{"conversationId":"{conversation}","workspaceId":"{workspace}","streamVersion":1,"committedAt":1}}"#), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_conversation","conversationId":"{conversation}","workspaceId":"{workspace}","streamVersion":1,"committedAt":1}}}}"#)),
            Self::GenerateCompleted => { let (ack, durable) = generation("completed"); (format!("POST /v1/conversations/{conversation}/messages HTTP/1.1"), 200, ack, durable) }
            Self::GenerateRejected => { let (ack, durable) = generation("rejected"); (format!("POST /v1/conversations/{conversation}/messages HTTP/1.1"), 200, ack, durable) }
            Self::GenerateProhibited => { let (ack, durable) = generation("prohibited_input_rejected"); (format!("POST /v1/conversations/{conversation}/messages HTTP/1.1"), 200, ack, durable) }
        }
    }

    const fn expects_success(self) -> bool {
        matches!(self, Self::CreateProject | Self::RenameProject | Self::ArchiveProject | Self::DeleteProject | Self::CreateWorkspace | Self::OpenWorkspace | Self::CreateConversation | Self::GenerateCompleted)
    }
}

#[tokio::test]
async fn every_non_bind_mutation_posts_once_then_persists_typed_durable_reconciliation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000911").expect("project");
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000912").expect("workspace");
    let conversation = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000913").expect("conversation");
    for case in [NetworkMutationCase::RenameProject, NetworkMutationCase::CreateProject, NetworkMutationCase::ArchiveProject, NetworkMutationCase::DeleteProject, NetworkMutationCase::CreateWorkspace, NetworkMutationCase::OpenWorkspace, NetworkMutationCase::CreateConversation, NetworkMutationCase::GenerateCompleted, NetworkMutationCase::GenerateRejected, NetworkMutationCase::GenerateProhibited] {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let (path, ack_status, ack, durable) = case.wire(project, workspace, conversation);
        let server = tokio::spawn(async move {
            let mut paths = Vec::new();
            for (status, body) in [(ack_status, ack), (200, durable)] {
                let (mut stream, _) = listener.accept().await.expect("request");
                let mut bytes = [0; 8192];
                let used = stream.read(&mut bytes).await.expect("read");
                paths.push(String::from_utf8_lossy(&bytes[..used]).into_owned());
                let reply = format!("HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                stream.write_all(reply.as_bytes()).await.expect("reply");
            }
            paths
        });
        let directory = tempfile::tempdir().expect("directory");
        let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), reconcile_client(&origin)).expect("core");
        let request = case.request(project, workspace, conversation);
        let replay = request.clone();
        let lease = core.prepare_mutation(request).await.expect("prepare");
        let result = core.dispatch_prepared_mutation(lease).await;
        if case.expects_success() {
            if let Err(error) = result { panic!("dispatch {path} failed: {error}"); }
        } else {
            assert!(matches!(result, Err(AppCoreError::GenerationRejected | AppCoreError::ProhibitedInputRejected)));
        }
        let paths = server.await.expect("server");
        assert!(paths[0].starts_with(&path), "wrong mutation path: {}", paths[0]);
        assert!(paths[1].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
        assert!(paths.iter().all(|request| !request.starts_with("GET ")));
        assert_eq!(
            core.prepare_mutation(replay).await.expect("canonical record").anchored_record.disposition(),
            runne_local_store::ClientMutationDisposition::CanonicalOutcome,
        );
    }
}

#[tokio::test]
async fn uncertain_generation_is_exposed_as_unknown_without_generation_rejection_or_retry() {
    let (project, workspace, conversation) = matrix_values();
    let (origin, server) = matrix_server(vec![(
        502,
        r#"{"code":"conversation_outcome_unknown","requestId":"018f2e3a-7000-7000-8000-000000000929"}"#.into(),
    )])
    .await;
    let (_directory, core) = matrix_core(&origin);
    let request = NetworkMutationCase::GenerateCompleted.request(project, workspace, conversation);
    let replay = request.clone();
    let result = core
        .dispatch_prepared_mutation(core.prepare_mutation(request).await.expect("prepare"))
        .await;
    assert!(matches!(result, Err(AppCoreError::GenerationOutcomeUnknown)));
    assert_eq!(
        core.prepare_mutation(replay)
            .await
            .expect("replay record")
            .anchored_record
            .disposition(),
        runne_local_store::ClientMutationDisposition::Reconciling
    );
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /v1/conversations/"));
}
