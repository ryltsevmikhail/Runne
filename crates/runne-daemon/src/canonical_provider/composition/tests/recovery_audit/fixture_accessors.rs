impl Harness {
    pub(super) const fn generation(&self) -> u64 {
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

    pub(super) fn query_connection(&self) -> runne_store::schema::ManagedConnection {
        managed_test_connection(
            &self.db_path,
            self.authority,
            self.lineage,
            runne_store::schema::ConnectionMode::Reader,
        )
    }

    pub(super) fn writer_connection(&self) -> runne_store::schema::ManagedConnection {
        managed_test_connection(
            &self.db_path,
            self.authority,
            self.lineage,
            runne_store::schema::ConnectionMode::ValidatedReopen,
        )
    }

    pub(super) fn begin(
        &self,
    ) -> (
        ApplicationCommandContext,
        runne_application::ports::TextGenerationReceipt,
    ) {
        let conversation_id = "018f2e3a-7000-7000-8000-000000000091"
            .parse()
            .unwrap();
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
