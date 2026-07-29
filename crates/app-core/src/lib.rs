//! Platform-neutral application orchestration.

use std::path::Path;
use std::sync::Mutex;

use gocode_local_store::{
    LocalProject, LocalStore, ProjectOpenError, SecurityTransactionError, StoreOpenError,
};
pub use gocode_runtime_client::RuntimeConnectionState as RuntimeAvailability;
use serde::Serialize;
use thiserror::Error;

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
}

impl AppCore {
    /// Opens the application service for one profile database.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the profile cannot be opened or migrated.
    pub fn open(path: &Path) -> Result<Self, AppCoreError> {
        Ok(Self {
            store: Mutex::new(LocalStore::open(path)?),
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
        load_bootstrap(&store)
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
            runtime: RuntimeAvailability::Unconfigured,
        })
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
