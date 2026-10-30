use super::{
    BackendOwner, CanonicalId, CreateProjectRequest, CreateWorkspaceRequest,
    ExistingWorkspaceRequest, ProjectTrustControlRequestDto, ProjectTrustDecisionDto,
    ProjectTrustStatusDto, VerifiedRootHandle, api, identity,
};
#[path = "registration_intent.rs"]
mod intent;

impl BackendOwner {
    pub const fn registration_retry_safe(&self) -> bool {
        (self.pending_registration.is_some() || self.registration_intent_saved)
            && self.workspace_id.is_none()
    }

    pub const fn registration_status(&self) -> &'static str {
        registration_status(self.pending_registration.is_some())
    }

    pub(super) async fn bind_existing(&mut self, workspace_id: CanonicalId) -> Result<(), String> {
        let workspace = self.client.get_workspace(workspace_id).await.map_err(api)?;
        let trust = self
            .client
            .get_project_trust(workspace.project_id(), workspace_id)
            .await
            .map_err(api)?;
        // Exact-root lookup established identity, but never establishes consent.
        self.pending_registration = Some(workspace_id);
        if !workspace.is_open() || trust.status() != ProjectTrustStatusDto::Trusted {
            return Ok(());
        }
        let root_version = self.bind(workspace_id, workspace.version()).await?;
        let current = self
            .client
            .get_project_trust(workspace.project_id(), workspace_id)
            .await
            .map_err(api)?;
        if current.status() == ProjectTrustStatusDto::Trusted
            && current.workspace_version() == root_version
            && current.root_admission_version().is_some()
        {
            self.workspace_id = Some(workspace_id);
            self.pending_registration = None;
        }
        Ok(())
    }

    /// Explicit /register consent creates a project or resumes the exact known workspace.
    /// Partial registration never grants trust or enables sends by itself.
    pub async fn register_project(&mut self) -> Result<(), String> {
        if self.workspace_id.is_some() || self.supervisor.is_none() {
            return Err("Registration requires an unbound protected owner".into());
        }
        let workspace_id = if let Some(id) = self.pending_registration {
            id
        } else {
            // Reconcile a previous root bind whose acknowledgement was interrupted.
            let root =
                VerifiedRootHandle::open(&self.project).map_err(|_| "Project root unavailable")?;
            if let Some(workspace) = self
                .client
                .find_workspace_by_root(root.filesystem_identity_digest())
                .await
                .map_err(api)?
            {
                workspace.id()
            } else {
                self.create_registration().await?
            }
        };
        self.pending_registration = Some(workspace_id);
        let mut workspace = self.client.get_workspace(workspace_id).await.map_err(api)?;
        if !workspace.is_open() {
            self.client
                .open_workspace(
                    ExistingWorkspaceRequest::new(identity()?, workspace_id, workspace.version())
                        .map_err(api)?,
                )
                .await
                .map_err(api)?;
            workspace = self.client.get_workspace(workspace_id).await.map_err(api)?;
        }
        // Always refresh the verified native root handle before explicit confirmation.
        let root_version = self.bind(workspace_id, workspace.version()).await?;
        let trust = self
            .client
            .get_project_trust(workspace.project_id(), workspace_id)
            .await
            .map_err(api)?;
        let request = confirmation_request(
            workspace.project_id(),
            workspace_id,
            trust.epoch(),
            trust.revision(),
            trust.project_version(),
            trust.workspace_version(),
            trust.root_admission_version(),
            root_version,
        )?;
        if trust.status() != ProjectTrustStatusDto::Trusted {
            let confirmed = self
                .client
                .decide_project_trust(request)
                .await
                .map_err(api)?;
            if confirmed.status() != ProjectTrustStatusDto::Trusted {
                return Err("Project registration was not confirmed; retry /register".into());
            }
        }
        self.workspace_id = Some(workspace_id);
        self.pending_registration = None;
        Ok(())
    }

    async fn create_registration(&mut self) -> Result<CanonicalId, String> {
        let root =
            VerifiedRootHandle::open(&self.project).map_err(|_| "Project root unavailable")?;
        let state =
            crate::state_dir::state_root().ok_or("Registration state directory unavailable")?;
        let journal = intent::Journal::open(
            &state,
            intent::scope(
                self.client.session_info(),
                &root.filesystem_identity_digest(),
            ),
        )?;
        let label = self
            .project
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Project");
        // Persist every resource/command identity before the first external mutation.
        let record = journal.load_or_create(label)?;
        self.registration_intent_saved = true;
        match self.client.get_project(record.project).await {
            Ok(_) => {}
            Err(error) if error.kind() == runne_runtime_client::RuntimeApiErrorKind::NotFound => {
                self.client
                    .create_project(
                        CreateProjectRequest::new(
                            record.project_identity()?,
                            record.project,
                            &record.label,
                        )
                        .map_err(api)?,
                    )
                    .await
                    .map_err(api)?;
            }
            Err(error) => return Err(api(error)),
        }
        match self.client.get_workspace(record.workspace).await {
            Ok(workspace) if workspace.project_id() == record.project => {}
            Ok(_) => return Err("Registration workspace belongs to a different project".into()),
            Err(error) if error.kind() == runne_runtime_client::RuntimeApiErrorKind::NotFound => {
                self.client
                    .create_workspace(
                        CreateWorkspaceRequest::new(
                            record.workspace_identity()?,
                            record.project,
                            record.workspace,
                            &record.label,
                        )
                        .map_err(api)?,
                    )
                    .await
                    .map_err(api)?;
            }
            Err(error) => return Err(api(error)),
        }
        Ok(record.workspace)
    }
}

const fn registration_status(pending: bool) -> &'static str {
    if pending {
        "Project registration incomplete — use /register to confirm the existing workspace; sending disabled"
    } else {
        "Project registration required — use /register to admit this root; sending disabled"
    }
}

#[allow(clippy::too_many_arguments)]
fn confirmation_request(
    project_id: CanonicalId,
    workspace_id: CanonicalId,
    epoch: u64,
    revision: u64,
    project_version: u64,
    workspace_version: u64,
    root_version: Option<u64>,
    admitted_workspace_version: u64,
) -> Result<ProjectTrustControlRequestDto, String> {
    if workspace_version != admitted_workspace_version {
        return Err("Workspace changed after root binding; retry /register".into());
    }
    if root_version.is_none() {
        return Err("Root admission not recorded; retry /register".into());
    }
    Ok(ProjectTrustControlRequestDto {
        project_id,
        workspace_id,
        decision: ProjectTrustDecisionDto::ConfirmProject,
        expected_epoch: epoch,
        expected_revision: revision,
        expected_project_version: project_version,
        expected_workspace_version: workspace_version,
        expected_root_admission_version: root_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resumed_confirmation_keeps_exact_workspace_and_current_fences() {
        let project = CanonicalId::now_v7();
        let workspace = CanonicalId::now_v7();
        assert!(confirmation_request(project, workspace, 4, 5, 6, 7, None, 7).is_err());
        assert!(confirmation_request(project, workspace, 4, 5, 6, 8, Some(8), 7).is_err());
        let request = confirmation_request(project, workspace, 4, 5, 6, 7, Some(8), 7).unwrap();
        assert_eq!(request.project_id, project);
        assert_eq!(request.workspace_id, workspace);
        assert_eq!(request.expected_epoch, 4);
        assert_eq!(request.expected_revision, 5);
        assert_eq!(request.expected_project_version, 6);
        assert_eq!(request.expected_workspace_version, 7);
        assert_eq!(request.expected_root_admission_version, Some(8));
    }
    #[test]
    fn incomplete_registration_is_actionable_and_never_advertises_ready() {
        assert!(registration_status(true).contains("/register"));
        assert!(registration_status(true).contains("existing workspace"));
        assert!(registration_status(true).contains("sending disabled"));
        assert!(registration_status(false).contains("sending disabled"));
    }
}
