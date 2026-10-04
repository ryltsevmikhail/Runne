impl Harness {
    pub(in crate::canonical_provider::composition::tests) fn text_service(
        &self,
    ) -> Arc<dyn ConversationTextCommandService> {
        Arc::clone(&self.conversation_service)
    }

    pub(in crate::canonical_provider::composition::tests) fn authority(
        &self,
    ) -> runne_application::ports::RuntimeAuthorityId {
        runne_application::ports::RuntimeAuthorityId(hex::encode(self.authority))
    }

    pub(in crate::canonical_provider::composition::tests) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn terminal_application(
        &self,
    ) -> runne_runtime::provider_execution::ConversationProviderTerminalApplication<StoreTransaction>
    {
        runne_runtime::provider_execution::ConversationProviderTerminalApplication::new(
            self.store.clone(),
            Arc::clone(&self.conversation_service),
        )
    }

    pub(super) fn keyring(&self) -> Arc<dyn ProviderJournalKeyring> {
        Arc::clone(&self.keyring)
    }

    pub(super) fn prohibited(&self) -> Arc<dyn ProhibitedContentPort> {
        Arc::clone(&self.prohibited)
    }

    pub(in crate::canonical_provider::composition::tests) fn query_connection(
        &self,
    ) -> runne_store::schema::ManagedConnection {
        managed_test_connection(
            &self.db_path,
            self.authority,
            self.lineage,
            runne_store::schema::ConnectionMode::Reader,
        )
    }

    pub(in crate::canonical_provider::composition::tests) fn writer_connection(
        &self,
    ) -> runne_store::schema::ManagedConnection {
        managed_test_connection(
            &self.db_path,
            self.authority,
            self.lineage,
            runne_store::schema::ConnectionMode::ValidatedReopen,
        )
    }

    pub(super) fn try_writer_connection(
        &self,
    ) -> Result<runne_store::schema::ManagedConnection, crate::error::DaemonError> {
        try_managed_test_connection(
            &self.db_path,
            self.authority,
            self.lineage,
            runne_store::schema::ConnectionMode::ValidatedReopen,
        )
        .map_err(|_| {
            crate::error::DaemonError::Bootstrap("validated test store reopen failed".into())
        })
    }

    pub(in crate::canonical_provider::composition::tests) fn begin(
        &self,
    ) -> (
        ApplicationCommandContext,
        runne_application::ports::TextGenerationReceipt,
    ) {
        let conversation_id = "018f2e3a-7000-7000-8000-000000000091".parse().unwrap();
        let create = command_context("018f2e3a-7000-7000-8000-000000000092", "audit-create");
        ConversationService::new(
            self.store.clone(),
            self.store.clone(),
            RuntimeAuthorityId(hex::encode(self.authority)),
        )
        .create_from_application(
            &create,
            CreateConversationInput {
                conversation_id,
                workspace_id: "018f2e3a-7000-7000-8000-000000000093"
                    .parse::<WorkspaceId>()
                    .unwrap(),
                command_id: create.command_id,
                idempotency_key: create.idempotency_key.clone(),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
        let begin = command_context("018f2e3a-7000-7000-8000-000000000094", "audit-begin");
        let started = self
            .conversation_service
            .begin_text(
                &begin,
                BeginConversationTextInput {
                    conversation_id,
                    expected_version: 1,
                    text: MessageText::new("fixture input").unwrap(),
                },
            )
            .unwrap();
        (begin, started)
    }
}
