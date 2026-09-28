impl AppCore {
    /// Reads runtime-owned safe Project Trust metadata.
    ///
    /// # Errors
    ///
    /// Returns `ProjectUnavailable` for malformed IDs and `RuntimeUnavailable`
    /// when the protected runtime cannot provide the authoritative snapshot.
    pub async fn get_project_trust_control(
        &self,
        project_id: &str,
        workspace_id: &str,
    ) -> Result<ProjectTrustControlSnapshotDto, AppCoreError> {
        let project = CanonicalId::parse(project_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        let workspace = CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        let _operation = self.runtime_operation.lock().await;
        self.live_runtime_client()?
            .get_project_trust(project, workspace)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    /// Sends one trust-control compare-and-set and never retries an uncertain result.
    ///
    /// # Errors
    ///
    /// Returns a typed control conflict, managed-policy refusal, unavailable root,
    /// or `TrustControlUnknownAfterSend` when the response cannot establish whether
    /// the administrative decision committed.
    pub async fn decide_project_trust_control(
        &self,
        request: ProjectTrustControlRequestDto,
    ) -> Result<ProjectTrustControlSnapshotDto, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.live_runtime_client()?
            .decide_project_trust(request)
            .await
            .map_err(|error| match error.kind() {
                RuntimeApiErrorKind::UnknownAfterSend => AppCoreError::TrustControlUnknownAfterSend,
                RuntimeApiErrorKind::Conflict => AppCoreError::TrustControlConflict,
                RuntimeApiErrorKind::ManagedPolicy => AppCoreError::TrustControlManagedPolicy,
                RuntimeApiErrorKind::RootUnavailable => AppCoreError::TrustControlRootUnavailable,
                _ => AppCoreError::RuntimeUnavailable,
            })
    }
}
