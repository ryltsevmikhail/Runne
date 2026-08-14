impl AppCore {
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
