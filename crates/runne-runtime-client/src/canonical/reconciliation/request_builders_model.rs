use super::super::SubmitTaskRunRequest;
use super::{
    CanonicalId, CommandIdentity, CommandReconciliationRequest, CommandReconciliationWitness,
    RuntimeApiError, RuntimeApiErrorKind,
};

impl CommandReconciliationRequest {
    /// Builds a lost-ack reconciliation witness from the exact submit request.
    ///
    /// # Errors
    /// Returns `InvalidRequest` if the request's model or prompt is invalid.
    pub fn submit_task_run_from_request(
        request: &SubmitTaskRunRequest,
    ) -> Result<Self, RuntimeApiError> {
        let mut input = runne_api::TaskRunInput::new(request.prompt.clone())
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        if let Some(model) = &request.model {
            input = input.with_requested_model(model.clone()).map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        }
        if let Some(profile) = &request.selected_profile {
            input = input
                .with_selected_profile(profile.clone())
                .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        }
        if let Some(command) = &request.local_command {
            let executable = match command.executable() {
                runne_api::TaskRunExecutable::WorkspaceRelative(value) => {
                    super::ReconciliationExecutableWire::WorkspaceRelative(value.clone())
                }
                runne_api::TaskRunExecutable::SystemProgram(value) => {
                    super::ReconciliationExecutableWire::SystemProgram(value.clone())
                }
            };
            let wire = super::ReconciliationLocalCommandWire {
                executable,
                cwd: command.cwd().to_owned(),
                argv: command.argv().to_vec(),
                env: command.env().iter().map(|(key, value)| {
                    super::ReconciliationEnvironmentWire { key: key.clone(), value: value.clone() }
                }).collect(),
            };
            input = input.with_local_command(command.clone())
                .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
            let profile = input.selected_profile().map(|profile| super::ReconciliationProfileWire {
                profile_id: profile.profile_id().to_owned(),
                profile_digest: hex::encode(profile.profile_digest()),
            });
            return Ok(Self {
                identity: request.identity.clone(),
                witness: CommandReconciliationWitness::SubmitTaskRun {
                    conversation_id: request.conversation_id,
                    workspace_id: request.workspace_id,
                    prompt: Some(input.prompt().to_owned()),
                    model: input.requested_model().map(str::to_owned),
                    profile,
                    local_command: Some(wire),
                },
            });
        }
        let profile = input
            .selected_profile()
            .map(|profile| super::ReconciliationProfileWire {
                profile_id: profile.profile_id().to_owned(),
                profile_digest: hex::encode(profile.profile_digest()),
            });
        Ok(Self {
            identity: request.identity.clone(),
            witness: CommandReconciliationWitness::SubmitTaskRun {
                conversation_id: request.conversation_id,
                workspace_id: request.workspace_id,
                prompt: Some(input.prompt().to_owned()),
                model: input.requested_model().map(str::to_owned),
                profile,
                local_command: None,
            },
        })
    }

    /// Builds a submit reconciliation witness with the exact explicit model.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the prompt or model is invalid.
    pub fn submit_task_run_with_model(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        prompt: impl Into<String>,
        model: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        let prompt = prompt.into();
        let model = model.into();
        runne_api::TaskRunInput::new(prompt.clone())
            .and_then(|input| input.with_requested_model(model.clone()))
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::SubmitTaskRun {
                conversation_id,
                workspace_id,
                prompt: Some(prompt),
                model: Some(model),
                profile: None,
                local_command: None,
            },
        })
    }

    /// Builds a submit witness with an exact profile id and digest.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the prompt is invalid.
    pub fn submit_task_run_with_profile(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        prompt: impl Into<String>,
        profile: &runne_api::SelectedProviderProfile,
    ) -> Result<Self, RuntimeApiError> {
        let prompt = prompt.into();
        runne_api::TaskRunInput::new(prompt.clone())
            .and_then(|input| input.with_selected_profile(profile.clone()))
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::SubmitTaskRun {
                conversation_id,
                workspace_id,
                prompt: Some(prompt),
                model: None,
                profile: Some(super::ReconciliationProfileWire {
                    profile_id: profile.profile_id().to_owned(),
                    profile_digest: hex::encode(profile.profile_digest()),
                }),
                local_command: None,
            },
        })
    }
}
