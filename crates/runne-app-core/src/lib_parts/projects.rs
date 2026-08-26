impl AppCore {
    /// Reads the complete bounded canonical Project projection from the runtime.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the authenticated runtime is not live or
    /// exceeds the host-owned pagination safety bound.
    pub async fn list_canonical_projects(
        &self,
    ) -> Result<Vec<CanonicalProjectSummary>, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let client = self.live_runtime_client()?;
        let mut cursor = None;
        let mut projects = Vec::with_capacity(project_page_capacity());
        for _ in 0..MAX_CANONICAL_PROJECT_PAGES {
            let page = client
                .list_projects(PROJECT_PAGE_LIMIT, cursor.as_ref())
                .await
                .map_err(|_| AppCoreError::RuntimeUnavailable)?;
            projects.extend(page.items().iter().map(CanonicalProjectSummary::from));
            match page.next_cursor().cloned() {
                None => return Ok(projects),
                Some(next) => cursor = Some(next),
            }
        }
        Err(AppCoreError::RuntimeUnavailable)
    }

    /// Reads one canonical Project and its bounded canonical Workspaces.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for malformed IDs, a non-live runtime, or a
    /// workspace sequence exceeding the host-owned pagination safety bound.
    pub async fn get_canonical_project(
        &self,
        project_id: &str,
    ) -> Result<CanonicalProjectDetails, AppCoreError> {
        let project_id = CanonicalId::parse(project_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        let _operation = self.runtime_operation.lock().await;
        let client = self.live_runtime_client()?;
        let project = client
            .get_project(project_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let mut cursor = None;
        let mut workspaces = Vec::with_capacity(workspace_page_capacity());
        for _ in 0..MAX_CANONICAL_WORKSPACE_PAGES {
            let page = client
                .list_workspaces(project_id, PROJECT_PAGE_LIMIT, cursor.as_ref())
                .await
                .map_err(|_| AppCoreError::RuntimeUnavailable)?;
            workspaces.extend(page.items().iter().map(CanonicalWorkspaceSummary::from));
            match page.next_cursor().cloned() {
                None => return Ok(CanonicalProjectDetails {
                    project: CanonicalProjectSummary::from(&project),
                    workspaces,
                }),
                Some(next) => cursor = Some(next),
            }
        }
        Err(AppCoreError::RuntimeUnavailable)
    }

    /// Reads one canonical Workspace from the authenticated runtime.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for malformed IDs or a non-live runtime.
    pub async fn get_canonical_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<CanonicalWorkspaceSummary, AppCoreError> {
        let workspace_id = CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        let _operation = self.runtime_operation.lock().await;
        self.live_runtime_client()?
            .get_workspace(workspace_id)
            .await
            .map(|workspace| CanonicalWorkspaceSummary::from(&workspace))
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    /// Records a native-only unresolved local root.
    ///
    /// # Errors
    ///
    /// Returns an error when locking, path validation or persistence fails.
    pub fn open_local_project(&self, path: &Path) -> Result<i64, AppCoreError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        Ok(store.open_local_project(path)?.id)
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
            .list_recent_roots()?
            .into_iter()
            .map(ProjectSummary::from)
            .collect())
    }

    /// Lists every canonical Workspace root for one Project ID.
    ///
    /// # Errors
    ///
    /// Returns an error when locking or persistence fails.
    pub fn get_project(&self, project_id: &str) -> Result<Vec<ProjectSummary>, AppCoreError> {
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        Ok(store
            .list_project_roots(project_id)?
            .into_iter()
            .map(ProjectSummary::from)
            .collect())
    }

    /// Loads exactly one canonical Workspace root.
    ///
    /// # Errors
    ///
    /// Returns an error when locking or canonical root storage fails.
    pub fn get_workspace(&self, workspace_id: &str) -> Result<Option<ProjectSummary>, AppCoreError> {
        let store = self.store.lock().map_err(|_| AppCoreError::StateUnavailable)?;
        Ok(store.get_workspace_root(workspace_id)?.map(ProjectSummary::from))
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
            runtime_mode: self.runtime_mode,
            runtime: self.effective_runtime_availability()?,
            runtime_lifecycle: self.runtime_lifecycle()?,
            runtime_failure: self.runtime_failure()?,
        })
    }
}

const PROJECT_PAGE_LIMIT: u16 = 100;
const MAX_CANONICAL_PROJECT_PAGES: usize = 10;
const MAX_CANONICAL_WORKSPACE_PAGES: usize = 10;

const fn project_page_capacity() -> usize {
    PROJECT_PAGE_LIMIT as usize * MAX_CANONICAL_PROJECT_PAGES
}

const fn workspace_page_capacity() -> usize {
    PROJECT_PAGE_LIMIT as usize * MAX_CANONICAL_WORKSPACE_PAGES
}

/// Renderer-safe, runtime-authoritative Project projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalProjectSummary {
    pub project_id: String,
    pub display_name: String,
    pub version: u64,
    pub archived: bool,
}

impl From<&runne_runtime_client::ProjectSnapshotDto> for CanonicalProjectSummary {
    fn from(value: &runne_runtime_client::ProjectSnapshotDto) -> Self {
        Self {
            project_id: value.id().to_string(),
            display_name: value.display_name().to_owned(),
            version: value.version(),
            archived: value.archived(),
        }
    }
}

/// Renderer-safe, runtime-authoritative Workspace projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkspaceSummary {
    pub workspace_id: String,
    pub project_id: String,
    pub display_name: String,
    pub version: u64,
    pub open: bool,
}

impl From<&runne_runtime_client::WorkspaceSnapshotDto> for CanonicalWorkspaceSummary {
    fn from(value: &runne_runtime_client::WorkspaceSnapshotDto) -> Self {
        Self {
            workspace_id: value.id().to_string(),
            project_id: value.project_id().to_string(),
            display_name: value.display_name().to_owned(),
            version: value.version(),
            open: value.is_open(),
        }
    }
}

/// Canonical Project plus its bounded Workspace projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalProjectDetails {
    pub project: CanonicalProjectSummary,
    pub workspaces: Vec<CanonicalWorkspaceSummary>,
}
