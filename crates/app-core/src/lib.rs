//! Platform-neutral application orchestration.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use gocode_local_store::{
    LocalProject, LocalStore, ProjectOpenError, SecurityTransactionError, StoreOpenError,
};
use gocode_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CommandIdentity, CreateConversationRequest,
    GenerateTextRequest, LocalProfileError, LocalRuntimeConnectError, LocalRuntimeProfile,
    ReplayAggregateKind, ReplayClientError, ReplayIdentityTracker, ReplayRecoveryDisposition,
    ReplayScope, ReplayStreamEvent, RuntimeApiErrorKind, default_local_profile_path,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod replay;

const RUNTIME_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONVERSATION_REFERENCE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Error)]
pub enum AppCoreError {
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("client storage unavailable")]
    StoreOpen(#[from] StoreOpenError),
    #[error("local project rejected")]
    Project(#[from] ProjectOpenError),
    #[error("stored theme is invalid")]
    InvalidTheme,
    #[error("application state unavailable")]
    StateUnavailable,
    #[error("diagnostics unavailable")]
    Diagnostics(#[from] SecurityTransactionError),
    #[error("runtime is unavailable")]
    RuntimeUnavailable,
    #[error("stored conversation reference is invalid")]
    InvalidConversationReference,
    #[error("project is unavailable")]
    ProjectUnavailable,
    #[error("runtime_identity_conflict")]
    RuntimeIdentityConflict,
    #[error("local_projection_unavailable")]
    LocalProjectionUnavailable,
    #[error("replay_resync_required")]
    ReplayResyncRequired,
    #[error("runtime_revoked")]
    RuntimeRevoked,
    #[error("runtime_incompatible")]
    RuntimeIncompatible,
}

/// Closed renderer-safe runtime connection disposition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAvailability {
    #[default]
    Unconfigured,
    ProfileLoaded,
    PeerVerified,
    BootstrapProved,
    Authenticated,
    Reconciling,
    Live,
    Reconnecting,
    Incompatible,
    Revoked,
    ResyncRequired,
    Fatal,
}

/// Invalid success-path runtime transition.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("runtime connection transition is invalid")]
pub struct RuntimeTransitionError;

impl RuntimeAvailability {
    pub const ALL: [Self; 12] = [
        Self::Unconfigured,
        Self::ProfileLoaded,
        Self::PeerVerified,
        Self::BootstrapProved,
        Self::Authenticated,
        Self::Reconciling,
        Self::Live,
        Self::Reconnecting,
        Self::Incompatible,
        Self::Revoked,
        Self::ResyncRequired,
        Self::Fatal,
    ];

    #[must_use]
    pub const fn allows_mutations(self) -> bool {
        matches!(self, Self::Live)
    }

    /// Applies one allowed closed state transition.
    ///
    /// # Errors
    ///
    /// Returns an error when peer, bootstrap or authentication proof would be
    /// skipped.
    pub const fn transition_to(self, next: Self) -> Result<Self, RuntimeTransitionError> {
        if matches!(
            (self, next),
            (Self::Unconfigured | Self::Reconnecting, Self::ProfileLoaded)
                | (Self::ProfileLoaded, Self::PeerVerified)
                | (Self::PeerVerified, Self::BootstrapProved)
                | (Self::BootstrapProved, Self::Authenticated)
                | (Self::Authenticated | Self::Live, Self::Reconciling)
                | (Self::Reconciling, Self::Live)
                | (
                    Self::ProfileLoaded
                        | Self::PeerVerified
                        | Self::BootstrapProved
                        | Self::Authenticated
                        | Self::Reconciling
                        | Self::Live,
                    Self::Reconnecting
                        | Self::Incompatible
                        | Self::Revoked
                        | Self::ResyncRequired
                        | Self::Fatal
                )
        ) {
            Ok(next)
        } else {
            Err(RuntimeTransitionError)
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct BootstrapState {
    pub theme: String,
    pub runtime: RuntimeAvailability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsSnapshot {
    pub app_version: String,
    pub platform: String,
    pub database_schema_version: u32,
    pub database_generation: u64,
    pub project_count: u64,
    pub runtime: RuntimeAvailability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSummary {
    pub id: i64,
    pub name: String,
    pub path: String,
    pub last_opened_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMessageSummary {
    pub message_id: String,
    pub role: String,
    pub task_run_id: String,
    pub attempt_id: String,
    pub text: String,
    pub committed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationSnapshot {
    pub conversation_id: String,
    pub projection_revision: u64,
    pub stream_version: u64,
    pub messages: Vec<ConversationMessageSummary>,
    pub recovery: ConversationRecoveryDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationRecoveryDisposition {
    Live,
    Reconnecting,
    Incompatible,
    Revoked,
    ResyncRequired,
    Fatal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationTimelineUpdate {
    pub conversation_id: String,
    pub projection_revision: u64,
    pub stream_version: u64,
    pub message: Option<ConversationMessageSummary>,
    pub recovery: ConversationRecoveryDisposition,
}

impl From<LocalProject> for ProjectSummary {
    fn from(project: LocalProject) -> Self {
        Self {
            id: project.id,
            name: project.name,
            path: project.path.to_string_lossy().into_owned(),
            last_opened_at: project.last_opened_at,
        }
    }
}

pub struct AppCore {
    store: Mutex<LocalStore>,
    runtime_profile_path: Option<PathBuf>,
    runtime_state: RwLock<RuntimeAvailability>,
    runtime_client: RwLock<Option<AuthenticatedRuntimeClient>>,
    runtime_connect: tokio::sync::Mutex<()>,
}

impl AppCore {
    /// Opens the application service for one profile database.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the profile cannot be opened or migrated.
    pub fn open(path: &Path) -> Result<Self, AppCoreError> {
        Self::open_internal(path, None)
    }

    /// Opens the application service with one host-owned runtime profile path.
    ///
    /// The path remains inside the Rust host and is never serialized to the
    /// renderer.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the desktop profile cannot be opened.
    pub fn open_with_runtime_profile(
        path: &Path,
        runtime_profile_path: PathBuf,
    ) -> Result<Self, AppCoreError> {
        Self::open_internal(path, Some(runtime_profile_path))
    }

    /// Opens the application service with the standard daemon-owned local
    /// runtime profile.
    ///
    /// # Errors
    ///
    /// Returns a storage or platform profile-resolution error.
    pub fn open_with_default_runtime_profile(path: &Path) -> Result<Self, AppCoreError> {
        let profile_path =
            default_local_profile_path().map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Self::open_with_runtime_profile(path, profile_path)
    }

    fn open_internal(
        path: &Path,
        runtime_profile_path: Option<PathBuf>,
    ) -> Result<Self, AppCoreError> {
        Ok(Self {
            store: Mutex::new(LocalStore::open(path)?),
            runtime_profile_path,
            runtime_state: RwLock::new(RuntimeAvailability::Unconfigured),
            runtime_client: RwLock::new(None),
            runtime_connect: tokio::sync::Mutex::new(()),
        })
    }

    /// Returns sanitized renderer bootstrap state.
    ///
    /// # Errors
    ///
    /// Returns an error when state locking, storage or validation fails.
    pub fn bootstrap(&self) -> Result<BootstrapState, AppCoreError> {
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let mut bootstrap = load_bootstrap(&store)?;
        drop(store);
        bootstrap.runtime = self.runtime_availability()?;
        Ok(bootstrap)
    }

    /// Loads the protected local profile and performs the authenticated exact
    /// profile handshake.
    ///
    /// # Errors
    ///
    /// Returns a redacted runtime failure and leaves a closed connection
    /// disposition for diagnostics/UI.
    pub async fn connect_runtime(&self) -> Result<RuntimeAvailability, AppCoreError> {
        let _connect = self.runtime_connect.lock().await;
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = None;
        let profile_path = self
            .runtime_profile_path
            .as_deref()
            .ok_or(AppCoreError::RuntimeUnavailable)?;
        let profile = match LocalRuntimeProfile::load(profile_path) {
            Ok(profile) => profile,
            Err(error) => {
                self.set_runtime_failure(map_profile_state(error))?;
                return Err(AppCoreError::RuntimeUnavailable);
            }
        };
        let current = self.runtime_availability()?;
        if !matches!(
            current,
            RuntimeAvailability::Unconfigured | RuntimeAvailability::Reconnecting
        ) {
            self.set_runtime_failure(RuntimeAvailability::Reconnecting)?;
        }
        self.transition_runtime(RuntimeAvailability::ProfileLoaded)?;
        let client = match profile.connect(RUNTIME_REQUEST_TIMEOUT).await {
            Ok(client) => client,
            Err(error) => {
                self.set_runtime_failure(map_connect_state(&error))?;
                return Err(AppCoreError::RuntimeUnavailable);
            }
        };
        self.transition_runtime(RuntimeAvailability::PeerVerified)?;
        self.transition_runtime(RuntimeAvailability::BootstrapProved)?;
        self.transition_runtime(RuntimeAvailability::Authenticated)?;
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = Some(client);
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        self.transition_runtime(RuntimeAvailability::Live)?;
        Ok(RuntimeAvailability::Live)
    }

    /// Creates or restores the one durable runtime Conversation bound to a
    /// local project.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed local reference, project, or runtime failure.
    pub async fn open_project_conversation(
        &self,
        project_id: i64,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let client = self.live_runtime_client()?;
        let reference = self.load_or_prepare_conversation_reference(project_id)?;
        let identity = replay::StableRuntimeIdentity::from_client(&client);
        if reference
            .bound()
            .is_some_and(|bound| !identity.matches_reference(bound))
        {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        let identity = CommandIdentity::new(
            reference.create_command_id(),
            reference.idempotency_key().to_owned(),
        )
        .map_err(|_| AppCoreError::InvalidConversationReference)?;
        let created = client
            .create_conversation(CreateConversationRequest::new(
                identity,
                reference.conversation_id(),
                reference.workspace_id(),
            ))
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        if created.conversation_id != reference.conversation_id()
            || created.workspace_id != reference.workspace_id()
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let stable_identity = replay::StableRuntimeIdentity::from_client(&client);
        let reference =
            self.bind_conversation_reference(project_id, reference, &stable_identity)?;
        self.reconcile_conversation(&client, &reference, &stable_identity, |_| {})
            .await
    }

    /// Sends one user message and returns the complete authoritative timeline.
    ///
    /// # Errors
    ///
    /// Returns a typed local/runtime failure without exposing credentials.
    pub async fn send_project_message(
        &self,
        project_id: i64,
        text: &str,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let current = self.open_project_conversation(project_id).await?;
        let conversation_id = CanonicalId::parse(&current.conversation_id)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        let client = self.live_runtime_client()?;
        let generated = client
            .generate_text(
                GenerateTextRequest::new(
                    new_command_identity()?,
                    conversation_id,
                    current.stream_version,
                    text,
                )
                .map_err(|_| AppCoreError::RuntimeUnavailable)?,
            )
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        if generated.conversation_id != conversation_id {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let reference = self.load_or_prepare_conversation_reference(project_id)?;
        let identity = replay::StableRuntimeIdentity::from_client(&client);
        if reference
            .bound()
            .is_none_or(|bound| !identity.matches_reference(bound))
        {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        self.reconcile_conversation(&client, &reference, &identity, |_| {})
            .await
    }

    /// Reconciles from the durable checkpoint and then emits acknowledged live
    /// Conversation updates until the stream terminates or the caller cancels
    /// the future.
    ///
    /// # Errors
    ///
    /// Returns a closed replay/local-store failure without exposing replay
    /// cursors or runtime credentials.
    #[allow(clippy::too_many_lines)]
    pub async fn subscribe_project_conversation<F>(
        &self,
        project_id: i64,
        mut on_update: F,
    ) -> Result<(), AppCoreError>
    where
        F: FnMut(ConversationTimelineUpdate) + Send,
    {
        let client = self.live_runtime_client()?;
        let reference = self.load_or_prepare_conversation_reference(project_id)?;
        let identity = replay::StableRuntimeIdentity::from_client(&client);
        let Some(bound) = reference.bound() else {
            return Err(AppCoreError::InvalidConversationReference);
        };
        if !identity.matches_reference(bound) {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        let scope_key = identity.scope(&reference);
        let checkpoint_result = {
            let store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            replay::checkpoint(&store, &scope_key)
        };
        let checkpoint = match checkpoint_result {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(error);
            }
        };
        let replay_scope = ReplayScope::new(
            ReplayAggregateKind::Conversation,
            reference.conversation_id(),
        );
        let mut local_error = None;
        let live_result = client
            .catch_up_from_persisted_cursor(
                replay_scope,
                checkpoint.as_ref().map(|value| value.cursor.as_str()),
                ReplayIdentityTracker::new(),
                |delivery| {
                    let Ok(mut store) = self.store.lock() else {
                        local_error = Some(AppCoreError::StateUnavailable);
                        return Err(());
                    };
                    match replay::apply_delivery(&mut store, &reference, &identity, delivery) {
                        Ok(update) => Ok(update),
                        Err(error) => {
                            local_error = Some(error);
                            Err(())
                        }
                    }
                },
                |update| {
                    if let Some(update) = update {
                        on_update(update);
                    }
                },
            )
            .await;
        let mut live = match live_result {
            Ok(live) => live,
            Err(_) if local_error.is_some() => {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(local_error
                    .take()
                    .unwrap_or(AppCoreError::LocalProjectionUnavailable));
            }
            Err(error) => return Err(self.map_replay_failure(&error)),
        };
        self.transition_runtime(RuntimeAvailability::Live)?;

        loop {
            match live
                .next_event()
                .await
                .map_err(|error| self.map_replay_failure(&error))?
            {
                ReplayStreamEvent::Heartbeat => {}
                ReplayStreamEvent::Terminal(terminal) => {
                    return Err(self.map_recovery_failure(terminal.recovery_disposition()));
                }
                ReplayStreamEvent::Delivery(delivery) => {
                    let update_result = {
                        let mut store = self
                            .store
                            .lock()
                            .map_err(|_| AppCoreError::StateUnavailable)?;
                        replay::apply_delivery(&mut store, &reference, &identity, &delivery)
                    };
                    let update = match update_result {
                        Ok(update) => update,
                        Err(error) => {
                            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                            return Err(error);
                        }
                    };
                    live.acknowledge(&delivery)
                        .await
                        .map_err(|error| self.map_replay_failure(&error))?;
                    if let Some(update) = update {
                        on_update(update);
                    }
                }
            }
        }
    }

    /// Persists a validated appearance theme.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, state locking or persistence fails.
    pub fn set_theme(&self, theme: &str) -> Result<(), AppCoreError> {
        if !matches!(theme, "dark" | "light") {
            return Err(AppCoreError::InvalidTheme);
        }
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        store.set_setting("appearance.theme", theme)?;
        drop(store);
        Ok(())
    }

    /// Persists a validated local directory as a project.
    ///
    /// # Errors
    ///
    /// Returns an error when locking, path validation or persistence fails.
    pub fn open_local_project(&self, path: &Path) -> Result<ProjectSummary, AppCoreError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        Ok(store.open_local_project(path)?.into())
    }

    /// Lists projects in most-recently-opened order.
    ///
    /// # Errors
    ///
    /// Returns an error when locking or persistence fails.
    pub fn list_projects(&self) -> Result<Vec<ProjectSummary>, AppCoreError> {
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        Ok(store
            .list_projects()?
            .into_iter()
            .map(ProjectSummary::from)
            .collect())
    }

    /// Loads one project by stable database id.
    ///
    /// # Errors
    ///
    /// Returns an error when locking or persistence fails.
    pub fn get_project(&self, id: i64) -> Result<Option<ProjectSummary>, AppCoreError> {
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        Ok(store.get_project(id)?.map(ProjectSummary::from))
    }

    /// Returns a bounded diagnostics snapshot without paths or content.
    ///
    /// # Errors
    ///
    /// Returns an error when state locking or metadata reads fail.
    pub fn diagnostics(
        &self,
        app_version: &str,
        platform: &str,
    ) -> Result<DiagnosticsSnapshot, AppCoreError> {
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let local = store.diagnostics()?;
        drop(store);
        Ok(DiagnosticsSnapshot {
            app_version: app_version.to_owned(),
            platform: platform.to_owned(),
            database_schema_version: local.schema_version,
            database_generation: local.database_generation,
            project_count: local.project_count,
            runtime: self.runtime_availability()?,
        })
    }

    fn runtime_availability(&self) -> Result<RuntimeAvailability, AppCoreError> {
        self.runtime_state
            .read()
            .map(|state| *state)
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn set_runtime_availability(
        &self,
        availability: RuntimeAvailability,
    ) -> Result<(), AppCoreError> {
        *self
            .runtime_state
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = availability;
        Ok(())
    }

    fn transition_runtime(&self, availability: RuntimeAvailability) -> Result<(), AppCoreError> {
        let current = self.runtime_availability()?;
        let next = current
            .transition_to(availability)
            .map_err(|_| AppCoreError::StateUnavailable)?;
        self.set_runtime_availability(next)
    }

    fn set_runtime_failure(&self, availability: RuntimeAvailability) -> Result<(), AppCoreError> {
        self.set_runtime_availability(availability)
    }

    fn runtime_client(&self) -> Result<Option<AuthenticatedRuntimeClient>, AppCoreError> {
        self.runtime_client
            .read()
            .map(|client| client.clone())
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn live_runtime_client(&self) -> Result<AuthenticatedRuntimeClient, AppCoreError> {
        if !self.runtime_availability()?.allows_mutations() {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.runtime_client()?
            .ok_or(AppCoreError::RuntimeUnavailable)
    }

    fn load_or_prepare_conversation_reference(
        &self,
        project_id: i64,
    ) -> Result<StoredConversationReference, AppCoreError> {
        if project_id <= 0 {
            return Err(AppCoreError::ProjectUnavailable);
        }
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        if store.get_project(project_id)?.is_none() {
            return Err(AppCoreError::ProjectUnavailable);
        }
        let key = format!("runtime.conversation.project.{project_id}");
        if let Some(serialized) = store.get_setting(&key)? {
            return parse_conversation_reference(&serialized);
        }
        let command_id = CanonicalId::now_v7();
        let reference = StoredConversationReference::V1(StoredConversationReferenceV1 {
            schema_version: 1,
            conversation_id: CanonicalId::now_v7(),
            workspace_id: CanonicalId::now_v7(),
            create_command_id: command_id,
            idempotency_key: command_id.to_string(),
        });
        let serialized = serde_json::to_string(&reference)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        store.set_setting(&key, &serialized)?;
        drop(store);
        Ok(reference)
    }

    fn bind_conversation_reference(
        &self,
        project_id: i64,
        reference: StoredConversationReference,
        identity: &replay::StableRuntimeIdentity,
    ) -> Result<StoredConversationReference, AppCoreError> {
        if let Some(bound) = reference.bound() {
            if identity.matches_reference(bound) {
                return Ok(reference);
            }
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        let bound = StoredConversationReference::V2(identity.bind_reference(&reference));
        let serialized = serde_json::to_string(&bound)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        store.set_setting(
            &format!("runtime.conversation.project.{project_id}"),
            &serialized,
        )?;
        drop(store);
        Ok(bound)
    }

    async fn reconcile_conversation<F>(
        &self,
        client: &AuthenticatedRuntimeClient,
        reference: &StoredConversationReference,
        identity: &replay::StableRuntimeIdentity,
        mut on_update: F,
    ) -> Result<ConversationSnapshot, AppCoreError>
    where
        F: FnMut(ConversationTimelineUpdate),
    {
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        let scope_key = identity.scope(reference);
        let checkpoint_result = {
            let store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            replay::checkpoint(&store, &scope_key)
        };
        let checkpoint = match checkpoint_result {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(error);
            }
        };
        let scope = ReplayScope::new(
            ReplayAggregateKind::Conversation,
            reference.conversation_id(),
        );
        let mut local_error = None;
        let result = client
            .catch_up_from_persisted_cursor(
                scope,
                checkpoint.as_ref().map(|value| value.cursor.as_str()),
                ReplayIdentityTracker::new(),
                |delivery| {
                    let Ok(mut store) = self.store.lock() else {
                        local_error = Some(AppCoreError::StateUnavailable);
                        return Err(());
                    };
                    match replay::apply_delivery(&mut store, reference, identity, delivery) {
                        Ok(update) => Ok(update),
                        Err(error) => {
                            local_error = Some(error);
                            Err(())
                        }
                    }
                },
                |update| {
                    if let Some(update) = update {
                        on_update(update);
                    }
                },
            )
            .await;
        if let Err(error) = result {
            if let Some(error) = local_error {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(error);
            }
            return Err(self.map_replay_failure(&error));
        }
        let snapshot_result = {
            let store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            replay::snapshot(&store, &scope_key, reference)
        };
        let snapshot = match snapshot_result {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(error);
            }
        };
        self.transition_runtime(RuntimeAvailability::Live)?;
        Ok(snapshot)
    }

    fn map_replay_failure(&self, error: &ReplayClientError) -> AppCoreError {
        self.map_recovery_failure(error.recovery_disposition())
    }

    fn map_recovery_failure(&self, recovery: ReplayRecoveryDisposition) -> AppCoreError {
        let (state, error) = match recovery {
            ReplayRecoveryDisposition::Reconnectable => (
                RuntimeAvailability::Reconnecting,
                AppCoreError::RuntimeUnavailable,
            ),
            ReplayRecoveryDisposition::Incompatible => (
                RuntimeAvailability::Incompatible,
                AppCoreError::RuntimeIncompatible,
            ),
            ReplayRecoveryDisposition::ResyncRequired => (
                RuntimeAvailability::ResyncRequired,
                AppCoreError::ReplayResyncRequired,
            ),
            ReplayRecoveryDisposition::Revoked => {
                (RuntimeAvailability::Revoked, AppCoreError::RuntimeRevoked)
            }
            ReplayRecoveryDisposition::Fatal => (
                RuntimeAvailability::Fatal,
                AppCoreError::RuntimeIdentityConflict,
            ),
        };
        let _ = self.set_runtime_failure(state);
        error
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum StoredConversationReference {
    V1(StoredConversationReferenceV1),
    V2(StoredConversationReferenceV2),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredConversationReferenceV1 {
    schema_version: u32,
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    create_command_id: CanonicalId,
    idempotency_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredConversationReferenceV2 {
    schema_version: u32,
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    create_command_id: CanonicalId,
    idempotency_key: String,
    runtime_authority: String,
    principal: String,
    lineage: String,
    profile_id: String,
    schema_hash: String,
    capability_digest: String,
}

impl StoredConversationReference {
    const fn conversation_id(&self) -> CanonicalId {
        match self {
            Self::V1(reference) => reference.conversation_id,
            Self::V2(reference) => reference.conversation_id,
        }
    }

    const fn workspace_id(&self) -> CanonicalId {
        match self {
            Self::V1(reference) => reference.workspace_id,
            Self::V2(reference) => reference.workspace_id,
        }
    }

    const fn create_command_id(&self) -> CanonicalId {
        match self {
            Self::V1(reference) => reference.create_command_id,
            Self::V2(reference) => reference.create_command_id,
        }
    }

    fn idempotency_key(&self) -> &str {
        match self {
            Self::V1(reference) => &reference.idempotency_key,
            Self::V2(reference) => &reference.idempotency_key,
        }
    }

    const fn bound(&self) -> Option<&StoredConversationReferenceV2> {
        match self {
            Self::V1(_) => None,
            Self::V2(reference) => Some(reference),
        }
    }
}

fn parse_conversation_reference(value: &str) -> Result<StoredConversationReference, AppCoreError> {
    let reference: StoredConversationReference =
        serde_json::from_str(value).map_err(|_| AppCoreError::InvalidConversationReference)?;
    let valid_schema = matches!(
        &reference,
        StoredConversationReference::V1(value) if value.schema_version == 1
    ) || matches!(
        &reference,
        StoredConversationReference::V2(value)
            if value.schema_version == CONVERSATION_REFERENCE_SCHEMA_VERSION
                && !value.runtime_authority.is_empty()
                && !value.principal.is_empty()
                && !value.lineage.is_empty()
                && !value.profile_id.is_empty()
                && !value.schema_hash.is_empty()
                && !value.capability_digest.is_empty()
    );
    if !valid_schema
        || CommandIdentity::new(
            reference.create_command_id(),
            reference.idempotency_key().to_owned(),
        )
        .is_err()
    {
        return Err(AppCoreError::InvalidConversationReference);
    }
    Ok(reference)
}

fn new_command_identity() -> Result<CommandIdentity, AppCoreError> {
    let command_id = CanonicalId::now_v7();
    CommandIdentity::new(command_id, command_id.to_string())
        .map_err(|_| AppCoreError::RuntimeUnavailable)
}

const fn map_profile_state(error: LocalProfileError) -> RuntimeAvailability {
    match error {
        LocalProfileError::Unavailable => RuntimeAvailability::Reconnecting,
        LocalProfileError::InsecurePermissions | LocalProfileError::InvalidProfile => {
            RuntimeAvailability::Incompatible
        }
        LocalProfileError::InvalidCredential => RuntimeAvailability::Revoked,
    }
}

const fn map_connect_state(error: &LocalRuntimeConnectError) -> RuntimeAvailability {
    match error {
        LocalRuntimeConnectError::Transport(_) => RuntimeAvailability::Reconnecting,
        LocalRuntimeConnectError::Api(error) => match error.kind() {
            RuntimeApiErrorKind::Unauthorized => RuntimeAvailability::Revoked,
            RuntimeApiErrorKind::Incompatible | RuntimeApiErrorKind::InvalidResponse => {
                RuntimeAvailability::Incompatible
            }
            RuntimeApiErrorKind::InvalidRequest
            | RuntimeApiErrorKind::NotFound
            | RuntimeApiErrorKind::Conflict
            | RuntimeApiErrorKind::Backpressure
            | RuntimeApiErrorKind::Unavailable
            | RuntimeApiErrorKind::ResponseTooLarge => RuntimeAvailability::Reconnecting,
        },
    }
}

/// Builds sanitized renderer bootstrap state.
///
/// # Errors
///
/// Returns a storage error when settings cannot be queried.
pub fn load_bootstrap(store: &LocalStore) -> Result<BootstrapState, AppCoreError> {
    let theme = match store.get_setting("appearance.theme")? {
        Some(theme) if matches!(theme.as_str(), "dark" | "light") => theme,
        Some(_) => return Err(AppCoreError::InvalidTheme),
        None => "dark".to_owned(),
    };
    Ok(BootstrapState {
        theme,
        runtime: RuntimeAvailability::Unconfigured,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AppCore, BootstrapState, CanonicalId, RuntimeAvailability, StoredConversationReference,
        StoredConversationReferenceV1, load_bootstrap,
    };
    use crate::replay::StableRuntimeIdentity;
    use gocode_local_store::LocalStore;

    #[test]
    fn bootstrap_reports_saved_theme_without_runtime_secrets() {
        let directory = tempfile::tempdir().expect("temp directory");
        let mut store =
            LocalStore::open(&directory.path().join("profile.sqlite3")).expect("open store");
        store
            .set_setting("appearance.theme", "light")
            .expect("save theme");

        assert_eq!(
            BootstrapState {
                theme: "light".to_owned(),
                runtime: RuntimeAvailability::Unconfigured,
            },
            load_bootstrap(&store).expect("load bootstrap")
        );
    }

    #[test]
    fn theme_change_is_persisted_by_app_core() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        let core = AppCore::open(&path).expect("open core");

        core.set_theme("light").expect("save theme");
        drop(core);

        let reopened = AppCore::open(&path).expect("reopen core");
        assert_eq!("light", reopened.bootstrap().expect("load bootstrap").theme);
    }

    #[test]
    fn opening_a_project_makes_it_available_after_app_restart() {
        let directory = tempfile::tempdir().expect("temp directory");
        let database_path = directory.path().join("profile.sqlite3");
        let project_path = directory.path().join("project-one");
        std::fs::create_dir(&project_path).expect("create project directory");

        let project = {
            let core = AppCore::open(&database_path).expect("open core");
            core.open_local_project(&project_path)
                .expect("open local project")
        };

        let reopened = AppCore::open(&database_path).expect("reopen core");
        let projects = reopened.list_projects().expect("list projects");
        let restored = reopened
            .get_project(project.id)
            .expect("get project")
            .expect("stored project");

        assert_eq!(projects, vec![project.clone()]);
        assert_eq!(restored, project);
    }

    #[test]
    fn diagnostics_expose_counts_and_generations_without_project_paths() {
        let directory = tempfile::tempdir().expect("temp directory");
        let database_path = directory.path().join("profile.sqlite3");
        let project_path = directory.path().join("private-project-name");
        std::fs::create_dir(&project_path).expect("create project directory");
        let core = AppCore::open(&database_path).expect("open core");
        core.open_local_project(&project_path)
            .expect("open project");

        let diagnostics = core
            .diagnostics("0.1.0", "macos")
            .expect("read diagnostics");
        let rendered = format!("{diagnostics:?}");

        assert_eq!(diagnostics.app_version, "0.1.0");
        assert_eq!(diagnostics.platform, "macos");
        assert_eq!(diagnostics.database_schema_version, 4);
        assert_eq!(diagnostics.database_generation, 1);
        assert_eq!(diagnostics.project_count, 1);
        assert_eq!(diagnostics.runtime, RuntimeAvailability::Unconfigured);
        assert!(!rendered.contains("private-project-name"));
        assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn conversation_reference_v2_contains_only_stable_authenticated_identity() {
        let command_id = CanonicalId::now_v7();
        let reference = StoredConversationReference::V1(StoredConversationReferenceV1 {
            schema_version: 1,
            conversation_id: CanonicalId::now_v7(),
            workspace_id: CanonicalId::now_v7(),
            create_command_id: command_id,
            idempotency_key: command_id.to_string(),
        });
        let identity = StableRuntimeIdentity {
            authority: "018f2e3a-7000-7000-8000-000000000120".to_owned(),
            principal: "local-owner".to_owned(),
            lineage: "018f2e3a-7000-7000-8000-000000000121".to_owned(),
            profile_id: "gocode-ui-client/1".to_owned(),
            schema_hash: "11".repeat(32),
            capability_digest: "22".repeat(32),
            binding_digest: "33".repeat(32),
            launch_generation: 9,
        };

        let bound = identity.bind_reference(&reference);
        assert!(identity.matches_reference(&bound));
        for mutate in [
            |value: &mut StableRuntimeIdentity| value.authority = "changed".to_owned(),
            |value: &mut StableRuntimeIdentity| value.principal = "changed".to_owned(),
            |value: &mut StableRuntimeIdentity| value.lineage = "changed".to_owned(),
            |value: &mut StableRuntimeIdentity| value.profile_id = "changed".to_owned(),
            |value: &mut StableRuntimeIdentity| value.schema_hash = "changed".to_owned(),
            |value: &mut StableRuntimeIdentity| value.capability_digest = "changed".to_owned(),
        ] {
            let mut changed = identity.clone();
            mutate(&mut changed);
            assert!(!changed.matches_reference(&bound));
        }

        let serialized = serde_json::to_value(bound).expect("serialize");
        let object = serialized.as_object().expect("reference object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "capabilityDigest",
                "conversationId",
                "createCommandId",
                "idempotencyKey",
                "lineage",
                "principal",
                "profileId",
                "runtimeAuthority",
                "schemaHash",
                "schemaVersion",
                "workspaceId",
            ]
        );
        assert_eq!(object["schemaVersion"], 2);
        let encoded = serde_json::to_string(object).expect("encode reference");
        for forbidden in [
            "instance",
            "generation",
            "session",
            "endpoint",
            "secret",
            "cursor",
            "certificate",
            "credential",
        ] {
            assert!(!encoded.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn reference_identity_conflict_is_fatal_and_does_not_rewrite_reference() {
        let directory = tempfile::tempdir().expect("temp directory");
        let database_path = directory.path().join("profile.sqlite3");
        let project_path = directory.path().join("project");
        std::fs::create_dir(&project_path).expect("create project");
        let core = AppCore::open(&database_path).expect("open core");
        let project = core
            .open_local_project(&project_path)
            .expect("open project");
        let reference = core
            .load_or_prepare_conversation_reference(project.id)
            .expect("v1 reference");
        let first = StableRuntimeIdentity {
            authority: "authority-a".to_owned(),
            principal: "principal".to_owned(),
            lineage: "lineage".to_owned(),
            profile_id: "profile".to_owned(),
            schema_hash: "11".repeat(32),
            capability_digest: "22".repeat(32),
            binding_digest: "33".repeat(32),
            launch_generation: 1,
        };
        let bound = core
            .bind_conversation_reference(project.id, reference, &first)
            .expect("bind reference");
        let key = format!("runtime.conversation.project.{}", project.id);
        let before = {
            let store = core.store.lock().expect("store");
            store.get_setting(&key).expect("read").expect("reference")
        };
        let mut conflicting = first;
        conflicting.authority = "authority-b".to_owned();

        let error = core
            .bind_conversation_reference(project.id, bound, &conflicting)
            .expect_err("identity conflict");
        assert_eq!(error.to_string(), "runtime_identity_conflict");
        assert_eq!(
            core.runtime_availability().expect("state"),
            RuntimeAvailability::Fatal
        );
        let after = {
            let store = core.store.lock().expect("store");
            store.get_setting(&key).expect("read").expect("reference")
        };
        assert_eq!(after.as_bytes(), before.as_bytes());
    }
}
