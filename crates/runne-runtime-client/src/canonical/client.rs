/// Authenticated runtime client. Construction is possible only after the
/// exact profile handshake succeeds.
#[derive(Clone)]
pub struct AuthenticatedRuntimeClient {
    client: reqwest::Client,
    origin: String,
    authority: RuntimeSessionAuthority,
    session: RuntimeSessionInfo,
    provider_statuses: Vec<runne_api::ProviderStatusSnapshotV1>,
    transport_kind: RuntimeTransportKind,
}

impl AuthenticatedRuntimeClient {
    /// Returns the accepted exact runtime profile.
    #[must_use]
    pub const fn session_info(&self) -> &RuntimeSessionInfo {
        &self.session
    }

    /// Returns the authenticated runtime's safe provider readiness projection.
    #[must_use]
    pub fn provider_statuses(&self) -> &[runne_api::ProviderStatusSnapshotV1] {
        &self.provider_statuses
    }

    /// Reads sanitized quota evidence from the authenticated runtime owner.
    ///
    /// The route only returns captured provider or local evidence; it does not
    /// trigger a provider quota request or carry credential material.
    ///
    /// # Errors
    ///
    /// Returns an error when the authenticated runtime rejects the request,
    /// transport fails, or the response is malformed.
    pub async fn provider_quota(
        &self,
    ) -> Result<Vec<runne_api::ProviderQuotaProjectionV1>, RuntimeApiError> {
        let response = self
            .authenticated_request(self.client.get(self.url("/v1/runtime/provider-quota")))?
            .send()
            .await
            .map_err(map_transport)?;
        let projections: Vec<runne_api::ProviderQuotaProjectionV1> =
            read_success_json(response, &[200]).await?;
        if projections
            .iter()
            .any(|projection| projection.validate().is_err())
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(projections)
    }

    pub(crate) const fn replay_authority(&self) -> &RuntimeSessionAuthority {
        &self.authority
    }

    /// Returns the native-only transport class accepted during authentication.
    #[must_use]
    pub const fn transport_kind(&self) -> RuntimeTransportKind {
        self.transport_kind
    }

    /// Copies the in-memory session authority only for test-support leak audits.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn test_session_authority(&self) -> Zeroizing<[u8; 32]> {
        self.authority.test_material()
    }

    pub(crate) fn from_local_session(
        client: reqwest::Client,
        origin: String,
        authority: RuntimeSessionAuthority,
        session: RuntimeSessionInfo,
        provider_statuses: Vec<runne_api::ProviderStatusSnapshotV1>,
    ) -> Self {
        let authority = authority.bind_replay_session(session.replay_binding());
        Self {
            client,
            origin,
            authority,
            session,
            provider_statuses,
            transport_kind: RuntimeTransportKind::ExternalLocal,
        }
    }

    pub(crate) fn from_protected_bundled_session(
        client: reqwest::Client,
        origin: String,
        authority: RuntimeSessionAuthority,
        session: RuntimeSessionInfo,
        provider_statuses: Vec<runne_api::ProviderStatusSnapshotV1>,
    ) -> Self {
        let authority = authority.bind_replay_session(session.replay_binding());
        Self {
            client,
            origin,
            authority,
            session,
            provider_statuses,
            transport_kind: RuntimeTransportKind::ProtectedBundled,
        }
    }

    /// Creates one durable Conversation.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure.
    pub async fn create_conversation(
        &self,
        request: CreateConversationRequest,
    ) -> Result<ConversationCreated, RuntimeApiError> {
        let expected_conversation_id = request.conversation_id;
        let expected_workspace_id = request.workspace_id;
        let url = self.url("/v1/conversations");
        let body = serde_json::to_vec(&CreateConversationWire {
            conversation_id: request.conversation_id,
            workspace_id: request.workspace_id,
        })
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let response = self
            .command_request(self.client.post(url), &request.identity)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        let wire: ConversationCreatedWire = read_success_json(response, &[202]).await?;
        let created = ConversationCreated::from(wire);
        if created.conversation_id != expected_conversation_id
            || created.workspace_id != expected_workspace_id
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(created)
    }

    /// Appends user text and returns the completed durable local generation.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure.
    pub async fn generate_text(
        &self,
        request: GenerateTextRequest,
    ) -> Result<ConversationTextResult, RuntimeApiError> {
        let expected_conversation_id = request.conversation_id;
        let url = self.url(&format!(
            "/v1/conversations/{}/messages",
            request.conversation_id
        ));
        let body = serde_json::to_vec(&GenerateTextWire {
            expected_version: request.expected_version,
            text: &request.text,
        })
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let response = self
            .command_request(self.client.post(url), &request.identity)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        let wire: ConversationTextResultWire = read_success_json(response, &[200]).await?;
        let result = ConversationTextResult::try_from(wire)?;
        if result.conversation_id != expected_conversation_id {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(result)
    }

    /// Reads the authoritative committed Conversation timeline.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure.
    pub async fn list_messages(
        &self,
        conversation_id: CanonicalId,
    ) -> Result<ConversationMessages, RuntimeApiError> {
        let url = self.url(&format!("/v1/conversations/{conversation_id}/messages"));
        let response = self
            .authenticated_request(self.client.get(url))?
            .send()
            .await
            .map_err(map_transport)?;
        let wire: ConversationMessagesWire = read_success_json(response, &[200]).await?;
        let snapshot = ConversationMessages::try_from(wire)?;
        if snapshot.conversation_id != conversation_id {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(snapshot)
    }

    /// Reads the authoritative committed `TaskRun` snapshot.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure.
    pub async fn get_task_run(
        &self,
        task_run_id: CanonicalId,
    ) -> Result<TaskRunSnapshot, RuntimeApiError> {
        let url = self.url(&format!("/v1/task-runs/{task_run_id}"));
        let response = self
            .authenticated_request(self.client.get(url))?
            .send()
            .await
            .map_err(map_transport)?;
        let snapshot = TaskRunSnapshot::try_from(
            read_success_json::<TaskRunSnapshotWire>(response, &[200]).await?,
        )?;
        if snapshot.task_run_id() != task_run_id {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(snapshot)
    }

    /// Reads every authoritative `TaskRun` snapshot for lifecycle decisions.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure when the list cannot be
    /// read or contains an invalid canonical snapshot.
    pub async fn list_task_runs(&self) -> Result<Vec<TaskRunSnapshot>, RuntimeApiError> {
        let response = self
            .authenticated_request(self.client.get(self.url("/v1/task-runs")))?
            .send()
            .await
            .map_err(map_transport)?;
        let wire: TaskRunListWire = read_success_json(response, &[200]).await?;
        decode_task_run_list(wire)
    }

    /// Requests durable cancellation of an authoritative `TaskRun`.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure when the request is
    /// rejected or the acknowledgement is not the exact expected transition.
    pub async fn cancel_task_run(
        &self,
        request: CancelTaskRunRequest,
    ) -> Result<TaskRunCancellationAcknowledgement, RuntimeApiError> {
        let expected_task_run_id = request.task_run_id;
        let url = self.url(&format!("/v1/task-runs/{}/cancel", request.task_run_id));
        let body = serde_json::to_vec(&ExistingTaskRunWire {
            expected_version: request.expected_version,
        })
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let response = self
            .command_request(self.client.post(url), &request.identity)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        let acknowledgement = TaskRunCancellationAcknowledgement::try_from(
            read_success_json::<TaskRunCancellationAcknowledgementWire>(response, &[202]).await?,
        )?;
        if acknowledgement.task_run_id() != expected_task_run_id {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(acknowledgement)
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }

    pub(crate) fn authenticated_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, RuntimeApiError> {
        Ok(request
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, self.authority.authorization_header()?))
    }

    pub(crate) const fn http_client(&self) -> &reqwest::Client {
        &self.client
    }

    fn command_request(
        &self,
        request: reqwest::RequestBuilder,
        identity: &CommandIdentity,
    ) -> Result<reqwest::RequestBuilder, RuntimeApiError> {
        Ok(self
            .authenticated_request(request)?
            .header("x-command-id", identity.command_id.to_string())
            .header("idempotency-key", identity.idempotency_key.as_str()))
    }
}
