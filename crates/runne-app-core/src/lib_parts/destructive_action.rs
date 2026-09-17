const MAX_DESTRUCTIVE_IMPACTS: u16 = 100;

/// Bounded asynchronous result of one trusted native confirmation request.
pub type DestructiveConfirmationFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Option<Box<dyn DestructiveConfirmationLease>>>
            + Send
            + 'a,
    >,
>;

/// Trusted desktop-host boundary for native destructive confirmation.
pub trait DestructiveConfirmationPort: Send + Sync {
    fn confirm(
        &self,
        context: DestructiveConfirmationContext,
    ) -> DestructiveConfirmationFuture<'_>;
}

/// Move-only confirmation capability issued only by the trusted native host.
pub trait DestructiveConfirmationLease: Send {
    /// Waits for the renderer to atomically consume the opaque native intent.
    fn wait_for_consume<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;

    /// Commits one consumed intent. It cannot be retried or recreated.
    fn try_commit(&mut self) -> bool;
}

/// The only destructive Project operations published by this capability wave.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectDestructiveOperation {
    Archive,
    Delete,
}

/// Safe, host-renderable detail from a fresh authoritative Project read.
///
/// The display name is copied from the same authoritative read that anchors
/// the mutation. It is suitable for native confirmation copy and keeps the
/// prompt understandable when several projects have similar rows in the
/// sidebar. Runtime version and other internal identifiers stay out of the
/// renderer-facing summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructiveProjectSummary {
    operation: ProjectDestructiveOperation,
    project_id: CanonicalId,
    display_name: String,
    expected_version: u64,
    impacted_workspaces: u16,
}

impl DestructiveProjectSummary {
    #[must_use]
    pub const fn operation(&self) -> ProjectDestructiveOperation { self.operation }
    #[must_use]
    pub const fn project_id(&self) -> CanonicalId { self.project_id }
    #[must_use]
    pub fn display_name(&self) -> &str { &self.display_name }
    #[must_use]
    pub const fn expected_version(&self) -> u64 { self.expected_version }
    #[must_use]
    pub const fn impacted_workspaces(&self) -> u16 { self.impacted_workspaces }
}

/// Closed host input for one native destructive confirmation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructiveConfirmationContext {
    summary: DestructiveProjectSummary,
    binding: MutationAdmissionBinding,
    action_digest: [u8; 32],
}

impl DestructiveConfirmationContext {
    #[must_use]
    pub fn summary(&self) -> DestructiveProjectSummary { self.summary.clone() }

    #[must_use]
    pub const fn binding(&self) -> MutationAdmissionBinding { self.binding }

    #[must_use]
    pub const fn action_digest(&self) -> [u8; 32] { self.action_digest }
}

/// Opaque move-only action prepared and anchored before native confirmation.
struct PreparedDestructiveProjectAction {
    lease: PreparedMutationLease,
    binding: MutationAdmissionBinding,
    summary: DestructiveProjectSummary,
    action_digest: [u8; 32],
}

impl std::fmt::Debug for PreparedDestructiveProjectAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedDestructiveProjectAction(<redacted>)")
    }
}

impl PreparedDestructiveProjectAction {
    fn context(&self) -> DestructiveConfirmationContext {
        DestructiveConfirmationContext {
            summary: self.summary.clone(),
            binding: self.binding,
            action_digest: self.action_digest,
        }
    }
}

/// Closes an anchored destructive action unless the coordinator completed it.
///
/// Closing is synchronous because V7 transitions are local durable operations;
/// this covers cancellation while an awaited native confirmation is in flight.
struct PreparedDestructiveActionGuard<'a> {
    core: &'a AppCore,
    action: Option<PreparedDestructiveProjectAction>,
}

impl<'a> PreparedDestructiveActionGuard<'a> {
    const fn new(core: &'a AppCore, action: PreparedDestructiveProjectAction) -> Self {
        Self { core, action: Some(action) }
    }

    fn context(&self) -> Result<DestructiveConfirmationContext, AppCoreError> {
        self.action
            .as_ref()
            .map(PreparedDestructiveProjectAction::context)
            .ok_or(AppCoreError::MutationUnavailable)
    }

    fn action_mut(&mut self) -> Result<&mut PreparedDestructiveProjectAction, AppCoreError> {
        self.action.as_mut().ok_or(AppCoreError::MutationUnavailable)
    }

    fn take(&mut self) -> Result<PreparedDestructiveProjectAction, AppCoreError> {
        self.action.take().ok_or(AppCoreError::MutationUnavailable)
    }
}

impl Drop for PreparedDestructiveActionGuard<'_> {
    fn drop(&mut self) {
        if let Some(action) = self.action.as_mut() {
            let _ = self.core.close_manual_resolution(&mut action.lease);
        }
    }
}

impl AppCore {
    /// Freshly reads, bounds impact enumeration, and anchors one destructive action.
    ///
    /// # Errors
    ///
    /// Returns a closed error unless the authoritative runtime, Project version,
    /// bounded impact page, and anchored Prepared V7 record all agree.
    async fn prepare_destructive_project_action(
        &self,
        operation: ProjectDestructiveOperation,
        project_id: CanonicalId,
        expected_version: u64,
    ) -> Result<PreparedDestructiveProjectAction, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let client = self.live_runtime_client()?;
        let identity = replay::StableRuntimeIdentity::from_client(&client);
        let project = client.get_project(project_id).await.map_err(|_| AppCoreError::RuntimeUnavailable)?;
        if project.version() != expected_version {
            return Err(AppCoreError::InvalidMutation);
        }
        let impacts = client
            .list_workspaces(project_id, MAX_DESTRUCTIVE_IMPACTS, None)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        if impacts.next_cursor().is_some() {
            return Err(AppCoreError::MutationUnavailable);
        }
        let request = match operation {
            ProjectDestructiveOperation::Archive => MutationRequest::archive_project(project_id, expected_version)?,
            ProjectDestructiveOperation::Delete => MutationRequest::delete_project(project_id, expected_version)?,
        };
        let action_digest = request.semantic_digest();
        let lease = self.prepare_mutation_under_operation(request)?;
        let binding = self.mutation_binding_for(&identity);
        if binding.gate_epoch != lease.gate_epoch {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        Ok(PreparedDestructiveProjectAction {
            lease,
            binding,
            action_digest,
            summary: DestructiveProjectSummary {
                operation,
                project_id,
                display_name: project.display_name().to_owned(),
                expected_version,
                impacted_workspaces: impacts.items().len().try_into().map_err(|_| AppCoreError::MutationUnavailable)?,
            },
        })
    }

    /// Revalidates the anchored binding then sends through the sole coordinator.
    ///
    /// # Errors
    ///
    /// Returns a closed error when runtime identity, gate epoch, or canonical
    /// reconciliation cannot be proven at dispatch time.
    async fn dispatch_destructive_project_action(
        &self,
        guard: &mut PreparedDestructiveActionGuard<'_>,
        confirmation: &mut dyn DestructiveConfirmationLease,
    ) -> Result<runne_runtime_client::ProjectCommandAcknowledgement, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let action = guard.action_mut()?;
        let current = self.mutation_binding_for(&action.lease.runtime_identity);
        if current != action.binding || current.gate_epoch != action.lease.gate_epoch
            || action.lease.request.semantic_digest() != action.action_digest {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let client = self.final_dispatch_client(&action.lease)?;
        let project = client
            .get_project(action.summary.project_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        if project.version() != action.summary.expected_version {
            return Err(AppCoreError::InvalidMutation);
        }
        if !confirmation.try_commit() {
            return Err(AppCoreError::MutationUnavailable);
        }
        // The native lease is committed. Give the coordinator ownership before
        // its first await so cancellation preserves Dispatching/Reconciliation
        // recovery evidence rather than rewriting it as ManualResolution.
        let mut action = guard.take()?;
        match self.dispatch_prepared_mutation_under_operation(
            &mut action.lease, None, false, false, false,
        ).await? {
            MutationDispatchResult::Project(ack) => Ok(ack),
            MutationDispatchResult::Workspace(_) | MutationDispatchResult::ConversationCreated(_) | MutationDispatchResult::TextGenerated(_) | MutationDispatchResult::TaskRunCancellationRequested(_) | MutationDispatchResult::ApprovalDecision(_) => Err(AppCoreError::InvalidMutation),
        }
    }

    /// Runs the only published destructive Project flow through a trusted host port.
    ///
    /// The prepared action never leaves `AppCore`; the port can approve only a
    /// redacted native summary and its authenticated binding.
    ///
    /// # Errors
    ///
    /// Returns a closed validation, storage, confirmation, runtime, or
    /// reconciliation error without exposing the prepared action.
    pub async fn execute_destructive_project_action(
        &self,
        operation: ProjectDestructiveOperation,
        project_id: CanonicalId,
        expected_version: u64,
        port: &dyn DestructiveConfirmationPort,
    ) -> Result<runne_runtime_client::ProjectCommandAcknowledgement, AppCoreError> {
        let action = self
            .prepare_destructive_project_action(operation, project_id, expected_version)
            .await?;
        let mut guard = PreparedDestructiveActionGuard::new(self, action);
        let Some(mut confirmation) = port.confirm(guard.context()?).await else {
            return Err(AppCoreError::MutationUnavailable);
        };
        if !confirmation.wait_for_consume().await {
            return Err(AppCoreError::MutationUnavailable);
        }
        let result = self
            .dispatch_destructive_project_action(&mut guard, confirmation.as_mut())
            .await?;
        Ok(result)
    }
}
