impl MutationRequest {
    /// Prepares a versioned rename under the anchored coordinator.
    ///
    /// # Errors
    /// Returns an error for an invalid version, name or target.
    pub fn rename_project(
        project_id: CanonicalId,
        expected_version: u64,
        display_name: String,
    ) -> Result<Self, AppCoreError> {
        Self::existing_project(
            runne_local_store::MutationOperation::ProjectRename,
            project_id,
            expected_version,
            CanonicalMutationCommand::RenameProject {
                project_id,
                display_name,
            },
        )
    }
}
