//! Protected process owner. Project mutations use runtime-client.
use runne_platform_desktop::{
    DevelopmentBundledRuntimeLauncher, ProtectedBundledRuntimeLaunchSpec,
    ProtectedBundledRuntimeSupervisor, VerifiedRootHandle, discover_bundled_runtime,
};
use runne_runtime_client::{
    AuthenticatedRuntimeClient, BindWorkspaceRootRequest, CanonicalId, CommandIdentity,
    CreateProjectRequest, CreateWorkspaceRequest, ExistingWorkspaceRequest,
    ProjectTrustControlRequestDto, ProjectTrustDecisionDto, ProjectTrustStatusDto,
    ProtectedRootAdmission,
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
const TIMEOUT: Duration = Duration::from_secs(30);
const RENEW_AFTER: Duration = Duration::from_mins(2);

pub struct BackendOwner {
    pub client: AuthenticatedRuntimeClient,
    pub workspace_id: Option<CanonicalId>,
    pub project_label: String,
    pub selected_profile: Option<runne_api::SelectedProviderProfile>,
    supervisor: Option<ProtectedBundledRuntimeSupervisor>,
    project: PathBuf,
    renewed_at: Instant,
    pending_registration: Option<CanonicalId>,
    registration_intent_saved: bool,
}

#[path = "owner_registration.rs"]
mod registration;
#[path = "owner_startup.rs"]
mod startup;

pub async fn resolve(project: PathBuf, profile: Option<PathBuf>) -> Result<BackendOwner, String> {
    Box::pin(startup::resolve(project, profile)).await
}

/// Starts an already-adopted installation; grants no trust or policy.
/// Workspace must come from the runtime exact-root lookup, never a label.
pub async fn start_protected(
    runtime_root: PathBuf,
    project: PathBuf,
    workspace: Option<CanonicalId>,
) -> Result<BackendOwner, String> {
    let project = project
        .canonicalize()
        .map_err(|_| "Project directory is unavailable")?;
    if !project.is_dir() || project.starts_with(&runtime_root) || runtime_root.starts_with(&project)
    {
        return Err("Project and runtime roots must be distinct directories".into());
    }
    runne_platform_desktop::require_linux_cli_baseline_root(&runtime_root)
        .map_err(|_| "Protected runtime root unavailable")?;
    let executable = std::env::current_exe().map_err(|_| "CLI image unavailable")?;
    let daemon = discover_bundled_runtime(&executable).map_err(|_| "Bundled daemon unavailable")?;
    let spec = ProtectedBundledRuntimeLaunchSpec::new(&daemon, &runtime_root)
        .map_err(|_| "Protected launch unavailable")?
        .with_provider_activation(
            runne_api::ProviderActivationBindingV1::deepseek_responses_text_v1(),
        );
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    supervisor
        .start()
        .map_err(|_| "Protected runtime failed to start")?;
    let connected = async {
        let profile = supervisor
            .take_runtime_profile()
            .ok_or("Protected profile unavailable")?;
        let client = profile
            .connect(TIMEOUT)
            .await
            .map_err(|_| "Protected authentication failed")?;
        supervisor
            .record_client_ready(&client)
            .map_err(|_| "Protected ready proof failed")?;
        let selected = tool_profile(&client)?;
        Ok::<_, String>((client, selected))
    }
    .await;
    let (client, selected_profile) = match connected {
        Ok(value) => value,
        Err(error) => {
            let _ = supervisor.stop();
            return Err(error);
        }
    };
    let mut owner = BackendOwner {
        client,
        workspace_id: None,
        project_label: project.display().to_string(),
        selected_profile: Some(selected_profile),
        supervisor: Some(supervisor),
        project,
        renewed_at: Instant::now(),
        pending_registration: None,
        registration_intent_saved: false,
    };
    if let Some(workspace) = workspace {
        owner.bind_existing(workspace).await?;
    }
    Ok(owner)
}

impl BackendOwner {
    pub async fn maintain(&mut self) -> Result<(), String> {
        if self.renewed_at.elapsed() < RENEW_AFTER {
            return Ok(());
        }
        self.renew_session().await?;
        // The daemon fences every admitted root handle during session rotation
        // (a rotated session must not outrun an in-flight root handoff), so a
        // renewed client that keeps serving loses workspace source access: F4
        // reports the diff API as unavailable and an already accepted coding
        // run fails its tool plan before any provider delivery.
        if let Err(error) = self.rebind_workspace_root().await {
            // Fail closed: without an admitted root every source-gated call is
            // denied, so stop accepting work and require an explicit /register.
            self.pending_registration = self.workspace_id.take().or(self.pending_registration);
            return Err(error);
        }
        self.renewed_at = Instant::now();
        Ok(())
    }

    /// Rotates the protected session without re-establishing the root handle.
    ///
    /// Kept separate from the re-bind so the two steps are individually
    /// observable: the rotation alone always leaves the runtime without an
    /// active root for this workspace until [`Self::rebind_workspace_root`].
    pub(crate) async fn renew_session(&mut self) -> Result<(), String> {
        let supervisor = self
            .supervisor
            .as_mut()
            .ok_or("Protected owner required for renewal")?;
        let profile = supervisor
            .renew_profile()
            .map_err(|_| "Protected renewal failed")?;
        let client = profile
            .connect(TIMEOUT)
            .await
            .map_err(|_| "Renewed authentication failed")?;
        supervisor
            .record_client_ready(&client)
            .map_err(|_| "Renewed identity mismatch")?;
        let selected = tool_profile(&client)?;
        if self.selected_profile.as_ref() != Some(&selected) {
            return Err("Tool profile changed during session renewal".into());
        }
        self.client = client;
        Ok(())
    }

    /// Re-establishes the exact admitted workspace root for the current session.
    ///
    /// This re-binds an existing trusted workspace: it never grants trust and
    /// never opens a closed workspace. A refused re-bind is returned as an
    /// error so the caller stops serving instead of silently losing root access.
    pub(crate) async fn rebind_workspace_root(&mut self) -> Result<(), String> {
        let Some(workspace) = self.workspace_id else {
            return Ok(());
        };
        let current = self.client.get_workspace(workspace).await.map_err(api)?;
        if !current.is_open() {
            return Err("Project workspace is no longer open".into());
        }
        let root_version = self.bind(workspace, current.version()).await?;
        let trust = self
            .client
            .get_project_trust(current.project_id(), workspace)
            .await
            .map_err(api)?;
        if trust.status() != ProjectTrustStatusDto::Trusted
            || trust.workspace_version() != root_version
            || trust.root_admission_version().is_none()
        {
            return Err("Workspace root re-admission was not confirmed".into());
        }
        Ok(())
    }

    async fn bind(&mut self, workspace: CanonicalId, version: u64) -> Result<u64, String> {
        let bytes: [u8; 16] = hex::decode(workspace.to_string().replace('-', ""))
            .map_err(|_| "Workspace identity invalid")?
            .try_into()
            .map_err(|_| "Workspace identity invalid")?;
        let root =
            VerifiedRootHandle::open(&self.project).map_err(|_| "Project root unavailable")?;
        let verified = self
            .supervisor
            .as_mut()
            .ok_or("Protected root owner unavailable")?
            .prepare_root_admission(&root, runne_api::WorkspaceId::from_bytes(bytes), version)
            .map_err(|_| "Root admission denied")?;
        let admission = ProtectedRootAdmission::from_verified(verified).map_err(api)?;
        let acknowledgement = self
            .client
            .bind_workspace_root(
                BindWorkspaceRootRequest::new(identity()?, workspace, version, &admission)
                    .map_err(api)?,
            )
            .await
            .map_err(api)?;
        Ok(acknowledgement.new_version())
    }
}

impl Drop for BackendOwner {
    fn drop(&mut self) {
        if let Some(supervisor) = self.supervisor.as_mut() {
            // Runtime shutdown owns effect reconciliation; never claim task cancellation.
            let _ = supervisor.stop();
        }
    }
}
fn identity() -> Result<CommandIdentity, String> {
    let id = CanonicalId::now_v7();
    CommandIdentity::new(id, format!("terminal-project-{id}")).map_err(api)
}
#[expect(clippy::needless_pass_by_value, reason = "map_err consumes its error")]
fn api(error: runne_runtime_client::RuntimeApiError) -> String {
    error.to_string()
}

fn tool_profile(
    client: &AuthenticatedRuntimeClient,
) -> Result<runne_api::SelectedProviderProfile, String> {
    let mut matching = client.provider_statuses().iter().filter(|status| {
        status.profile_id() == "runne-deepseek-responses-tools/1"
            && status.readiness() == runne_api::ProviderReadinessStatusV1::Ready
    });
    let status = matching.next().ok_or("Protected runtime has no ready finite DeepSeek coding grant; complete the explicit tool-budget opt-in")?;
    if matching.next().is_some() {
        return Err("Tool profile admission is ambiguous".into());
    }
    let digest: [u8; 32] = hex::decode(status.profile_digest())
        .map_err(|_| "Tool profile digest invalid")?
        .try_into()
        .map_err(|_| "Tool profile digest invalid")?;
    runne_api::SelectedProviderProfile::new(status.profile_id().to_owned(), digest)
        .map_err(|_| "Tool profile identity invalid".into())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "owner_renewal_tests.rs"]
mod renewal_tests;
