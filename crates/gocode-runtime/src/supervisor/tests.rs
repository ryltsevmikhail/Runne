
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use gocode_application::commands::{CommandOutcome, CreateTaskRunInput};
    use gocode_application::ports::{
        ApplicationCommandContext, PrincipalId, ProjectWorkspaceRepository, RuntimeAuthorityId,
    };
    use gocode_application::prohibited_content::ProhibitedContentPort;
    use gocode_domain::event::Actor;
    use gocode_domain::id::{ConversationId, IdempotencyKey, ProjectId, WorkspaceId};
    use gocode_domain::project_workspace::{
        Project, ProjectWorkspaceDisplayName as DisplayName, Workspace,
    };
    use gocode_security::SecretBroker;
    use gocode_store::store::StoreTransaction;
    use gocode_store::ProjectWorkspaceStore;

    type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

    fn available_guard() -> Arc<dyn ProhibitedContentPort> {
        Arc::new(SecretBroker::new().prohibited_content_guard())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn graceful_shutdown_completes_ingress_accepted_before_the_fence() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("runtime.sqlite");
        let authority = RuntimeAuthorityId("graceful-ingress-test".to_owned());
        let store = StoreTransaction::open(
            database_path.to_str().unwrap(),
            authority.clone(),
            available_guard(),
        )
        .unwrap();
        let project_id = "018f2e3a-7000-7000-8000-00000000000c"
            .parse::<ProjectId>()
            .unwrap();
        let workspace_id = "018f2e3a-7000-7000-8000-00000000000b"
            .parse::<WorkspaceId>()
            .unwrap();
        let projects = ProjectWorkspaceStore::from_store(store.clone());
        projects
            .create_project(
                "test",
                "018f2e3a-7000-7000-8000-00000000000d".parse().unwrap(),
                &IdempotencyKey::new("fixture-project").unwrap(),
                Project::create(project_id, DisplayName::new("Fixture".into()).unwrap()),
            )
            .unwrap();
        projects
            .create_workspace(
                "test",
                "018f2e3a-7000-7000-8000-00000000000e".parse().unwrap(),
                &IdempotencyKey::new("fixture-workspace").unwrap(),
                Workspace::create(
                    workspace_id,
                    project_id,
                    DisplayName::new("Fixture".into()).unwrap(),
                ),
            )
            .unwrap();
        let service: Arc<SqliteService> = Arc::new(TaskRunService::new(
            store.clone(),
            store.clone(),
            store,
            authority,
        ));
        let config = RuntimeConfig::default();
        let gate = Arc::new(AdmissionGate::new(config.max_in_flight_requests));
        let cancel = CancellationToken::new();
        let (ingress_tx, ingress_rx) = mpsc::channel(1);
        let (control_tx, control_rx) = mpsc::channel(1);
        let (drain_complete_tx, drain_complete_rx) = oneshot::channel();
        let (reply_tx, reply_rx) = oneshot::channel();
        let lease = InFlightLease::new(Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap());

        ingress_tx
            .send(AdmittedRequest {
                request: RuntimeRequest::Create {
                    context: ApplicationCommandContext {
                        command_id: "018f2e3a-7000-7000-8000-000000000001".parse().unwrap(),
                        idempotency_key: IdempotencyKey::new("accepted-before-fence").unwrap(),
                        principal_id: PrincipalId("test".to_owned()),
                        actor: Actor::new("test").unwrap(),
                    },
                    input: CreateTaskRunInput {
                        conversation_id: "018f2e3a-7000-7000-8000-00000000000a"
                            .parse::<ConversationId>()
                            .unwrap(),
                        workspace_id,
                    },
                    reply: reply_tx,
                },
                lease,
            })
            .await
            .unwrap();

        let (shutdown_ack_tx, shutdown_ack_rx) = oneshot::channel();
        control_tx
            .send(ControlCommand::Shutdown {
                mode: ShutdownMode::Graceful {
                    timeout: Duration::from_secs(5),
                },
                ack: shutdown_ack_tx,
            })
            .await
            .unwrap();

        tokio::spawn(run_supervisor(
            ingress_rx,
            control_rx,
            gate,
            config,
            cancel,
            service,
            None,
            None,
            drain_complete_tx,
        ));

        let command_outcome = tokio::time::timeout(Duration::from_secs(5), reply_rx)
            .await
            .expect("accepted command must complete before shutdown")
            .expect("accepted command reply sender must remain alive")
            .expect("accepted command must succeed");
        assert!(matches!(
            command_outcome,
            CommandOutcome::TaskRunCreated { .. }
        ));

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), shutdown_ack_rx)
                .await
                .expect("shutdown acknowledgement must be bounded")
                .expect("shutdown acknowledgement sender must remain alive"),
            ShutdownOutcome::Quiesced
        );
        assert_eq!(drain_complete_rx.await.unwrap(), ShutdownOutcome::Quiesced);
    }
}
