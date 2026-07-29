//! Platform-neutral application orchestration.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use gocode_local_store::{
    LocalProject, LocalStore, ProjectOpenError, SecurityTransactionError, StoreOpenError,
};
pub use gocode_runtime_client::RuntimeConnectionState as RuntimeAvailability;
use gocode_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CommandIdentity, ConversationMessageRole,
    ConversationMessages, CreateConversationRequest, GenerateTextRequest, LocalProfileError,
    LocalRuntimeConnectError, LocalRuntimeProfile, RuntimeApiErrorKind, default_local_profile_path,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const RUNTIME_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONVERSATION_REFERENCE_SCHEMA_VERSION: u32 = 1;

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMessageSummary {
    pub message_id: String,
    pub role: &'static str,
    pub task_run_id: String,
    pub attempt_id: String,
    pub text: String,
    pub committed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationSnapshot {
    pub conversation_id: String,
    pub stream_version: u64,
    pub messages: Vec<ConversationMessageSummary>,
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
        self.set_runtime_availability(RuntimeAvailability::Connecting)?;
        let profile = match LocalRuntimeProfile::load(profile_path) {
            Ok(profile) => profile,
            Err(error) => {
                self.set_runtime_availability(map_profile_state(error))?;
                return Err(AppCoreError::RuntimeUnavailable);
            }
        };
        self.set_runtime_availability(RuntimeAvailability::Authenticating)?;
        let client = match profile.connect(RUNTIME_REQUEST_TIMEOUT).await {
            Ok(client) => client,
            Err(error) => {
                self.set_runtime_availability(map_connect_state(&error))?;
                return Err(AppCoreError::RuntimeUnavailable);
            }
        };
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = Some(client);
        self.set_runtime_availability(RuntimeAvailability::Live)?;
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
        let identity = CommandIdentity::new(
            reference.create_command_id,
            reference.idempotency_key.clone(),
        )
        .map_err(|_| AppCoreError::InvalidConversationReference)?;
        let created = client
            .create_conversation(CreateConversationRequest::new(
                identity,
                reference.conversation_id,
                reference.workspace_id,
            ))
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        if created.conversation_id != reference.conversation_id
            || created.workspace_id != reference.workspace_id
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let snapshot = client
            .list_messages(reference.conversation_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        map_snapshot(snapshot, reference.conversation_id)
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
        let snapshot = client
            .list_messages(conversation_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        map_snapshot(snapshot, conversation_id)
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

    fn runtime_client(&self) -> Result<Option<AuthenticatedRuntimeClient>, AppCoreError> {
        self.runtime_client
            .read()
            .map(|client| client.clone())
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn live_runtime_client(&self) -> Result<AuthenticatedRuntimeClient, AppCoreError> {
        if self.runtime_availability()? != RuntimeAvailability::Live {
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
        let reference = StoredConversationReference {
            schema_version: CONVERSATION_REFERENCE_SCHEMA_VERSION,
            conversation_id: CanonicalId::now_v7(),
            workspace_id: CanonicalId::now_v7(),
            create_command_id: command_id,
            idempotency_key: command_id.to_string(),
        };
        let serialized = serde_json::to_string(&reference)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        store.set_setting(&key, &serialized)?;
        drop(store);
        Ok(reference)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredConversationReference {
    schema_version: u32,
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    create_command_id: CanonicalId,
    idempotency_key: String,
}

fn parse_conversation_reference(value: &str) -> Result<StoredConversationReference, AppCoreError> {
    let reference: StoredConversationReference =
        serde_json::from_str(value).map_err(|_| AppCoreError::InvalidConversationReference)?;
    if reference.schema_version != CONVERSATION_REFERENCE_SCHEMA_VERSION
        || CommandIdentity::new(
            reference.create_command_id,
            reference.idempotency_key.clone(),
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

fn map_snapshot(
    snapshot: ConversationMessages,
    expected_conversation_id: CanonicalId,
) -> Result<ConversationSnapshot, AppCoreError> {
    if snapshot.conversation_id != expected_conversation_id {
        return Err(AppCoreError::RuntimeUnavailable);
    }
    Ok(ConversationSnapshot {
        conversation_id: snapshot.conversation_id.to_string(),
        stream_version: snapshot.stream_version,
        messages: snapshot
            .messages
            .into_iter()
            .map(|message| ConversationMessageSummary {
                message_id: message.message_id.to_string(),
                role: match message.role {
                    ConversationMessageRole::User => "user",
                    ConversationMessageRole::Assistant => "assistant",
                },
                task_run_id: message.task_run_id.to_string(),
                attempt_id: message.attempt_id.to_string(),
                text: message.text,
                committed_at: message.committed_at,
            })
            .collect(),
    })
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
    use super::{AppCore, BootstrapState, RuntimeAvailability, load_bootstrap};
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
        assert_eq!(diagnostics.database_schema_version, 3);
        assert_eq!(diagnostics.database_generation, 1);
        assert_eq!(diagnostics.project_count, 1);
        assert_eq!(diagnostics.runtime, RuntimeAvailability::Unconfigured);
        assert!(!rendered.contains("private-project-name"));
        assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
    }
}
