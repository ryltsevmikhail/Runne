impl Harness {
    pub(super) fn issue_incomplete(
        &self,
        service: &DaemonCanonicalProviderService,
        seed: u8,
        streaming: bool,
    ) -> runne_provider::DispatchAttemptId {
        let (conversation_id, taskrun_id, attempt_id) = self.start_issue_taskrun(service, seed);
        let call = ProviderCall::new(
            ProviderCallId::from_bytes([seed; 16]),
            ModelRef::new(
                ProviderId::new(service.provider_id.as_ref()).unwrap(),
                service.model_id.as_ref(),
                service.model_revision.as_ref(),
            )
            .unwrap(),
            [seed.wrapping_add(1); 32],
            1_024,
            service.profile.call_binding_extension(),
        )
        .unwrap()
        .with_text_inputs(vec![
            ProviderTextInput::new(
                ProviderInputRole::User,
                format!("rotation-incomplete-{seed}"),
            )
            .unwrap(),
        ])
        .unwrap()
        .with_required_capabilities(vec![ProviderCapability::Streaming]);
        let prepared = service
            .adapter
            .prepare_for_digest_version(&call, runne_provider::ProviderCallDigestVersion::V2)
            .unwrap();
        let record = PreparedProviderRecord {
            call_id: call.call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: service.profile.profile_digest(),
        };
        service
            .dispatch_store
            .persist_prepared(&service.launch_capability, &record)
            .unwrap();
        let request = ProviderAuthorityIssueRequest {
            provider_id: call.model_ref().provider_id().clone(),
            principal_id: "local-owner".into(),
            conversation_id,
            taskrun_id,
            execution_attempt_id: attempt_id,
            prepared: ContractPreparedProviderRecord {
                call_id: record.call_id,
                call_digest_version: record.call_digest_version,
                prepared_digest: record.prepared_digest,
                render_digest: record.render_digest,
                profile_digest: record.profile_digest,
            },
            pricing_revision_digest: service.profile.pricing_revision_digest(),
            requested_input_tokens: 512,
            requested_output_tokens: 1_024,
            max_cost_micros: 50_000,
            currency: "USD".into(),
            provider_idempotency_key: format!("rotation-incomplete-{seed}"),
        };
        super::super::online_dispatch::start(
            service,
            self.writer_connection(),
            call,
            &request,
            streaming.then(|| ProviderStreamId::from_bytes([seed.wrapping_add(80); 16])),
            None,
        )
        .attempt_id
    }

    fn start_issue_taskrun(
        &self,
        service: &DaemonCanonicalProviderService,
        seed: u8,
    ) -> (ConversationId, TaskRunId, AttemptId) {
        let authority = runne_application::ports::RuntimeAuthorityId(hex::encode(self.authority));
        let workspace_id = "018f2e3a-7000-7000-8000-000000000093"
            .parse::<WorkspaceId>()
            .unwrap();
        let conversation_id: ConversationId =
            format!("018f2e3a-7000-7000-8000-{:012x}", 0x200 + u64::from(seed))
                .parse()
                .expect("deterministic UUIDv7 conversation ID");
        let tasks = TaskRunService::new(
            self.store.clone(),
            self.store.clone(),
            self.store.clone(),
            authority.clone(),
        );
        runne_store::execution_node::register_local_linux_node(
            &self.writer_connection(),
            self.authority,
            self.generation,
            runne_store::execution_node::LinuxNodeDescriptor { capacity: 2 },
            300,
        )
        .unwrap();
        let suffix = u64::from(seed) * 8;
        let create_context = command_context(
            &format!("018f2e3a-7000-7000-8000-{:012x}", 0x400 + suffix),
            &format!("rotation-create-{seed}"),
        );
        ConversationService::new(self.store.clone(), self.store.clone(), authority.clone())
            .create_from_application(
                &create_context,
                runne_api::CreateConversationInput {
                    conversation_id,
                    workspace_id,
                    command_id: create_context.command_id,
                    idempotency_key: create_context.idempotency_key.clone(),
                    scope: runne_api::ConversationContextScope::Workspace,
                },
            )
            .unwrap();
        let submit_context = command_context(
            &format!("018f2e3a-7000-7000-8000-{:012x}", 0x401 + suffix),
            &format!("rotation-submit-{seed}"),
        );
        let selected_profile = runne_domain::task_run::SelectedProviderProfile::new(
            service.profile.profile_id().to_owned(),
            service.profile.profile_digest(),
        )
        .unwrap();
        let input = TaskRunInput::new(format!("rotation-incomplete-{seed}"))
            .unwrap()
            .with_selected_profile(selected_profile)
            .unwrap();
        let outcome = tasks
            .submit_task_run(
                &submit_context,
                SubmitTaskRunInput {
                    conversation_id,
                    workspace_id,
                    input,
                },
            )
            .unwrap();
        let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
            outcome
        else {
            panic!("submitted TaskRun expected")
        };
        let claim_context = command_context(
            &format!("018f2e3a-7000-7000-8000-{:012x}", 0x402 + suffix),
            &format!("rotation-claim-{seed}"),
        );
        let claim = tasks
            .claim_task_run(
                &claim_context,
                ClaimTaskRunInput {
                    taskrun_id,
                    expected_version: 2,
                    node_id: ExecutionNodeId(uuid::Uuid::from_bytes(self.authority).to_string()),
                    node_epoch: self.generation,
                    capability_descriptor: "linux-executor-v1".into(),
                    lease_duration_ms: 300_000,
                },
                &self.store,
            )
            .unwrap();
        let runne_application::ports::TaskRunClaimResult::Committed(claim) = claim else {
            panic!("claim expected")
        };
        let identity = TaskRunAssignmentIdentity {
            taskrun_id,
            attempt_id: claim.attempt_id,
            node_id: claim.node_id,
            node_epoch: claim.node_epoch,
            fence: claim.fence,
        };
        let begin_context = command_context(
            &format!("018f2e3a-7000-7000-8000-{:012x}", 0x403 + suffix),
            &format!("rotation-begin-{seed}"),
        );
        self.conversation_service
            .begin_claimed_text(
                &begin_context,
                BeginClaimedConversationTextInput {
                    original: BeginConversationTextInput {
                        conversation_id,
                        expected_version: 1,
                        text: MessageText::new(format!("rotation-incomplete-{seed}")).unwrap(),
                    },
                    taskrun_id,
                    attempt_id: claim.attempt_id,
                    taskrun_version: claim.new_version,
                    workspace_id,
                    assignment: identity,
                },
            )
            .unwrap();
        (conversation_id, taskrun_id, claim.attempt_id)
    }
}
