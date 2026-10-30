use runne_runtime_client::{
    CanonicalId, CommandIdentity, CommandReconciliationRequest, RuntimeSessionInfo,
    SubmitTaskRunRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub version: u8,
    pub scope: String,
    pub command: CanonicalId,
    pub conversation: CanonicalId,
    pub workspace: CanonicalId,
    pub prompt: Option<String>,
    pub profile: Option<(String, String)>,
}

impl Pending {
    pub fn new(
        session: &RuntimeSessionInfo,
        workspace: CanonicalId,
        conversation: CanonicalId,
        prompt: Option<String>,
        profile: Option<&runne_api::SelectedProviderProfile>,
    ) -> Self {
        Self {
            version: 1,
            scope: scope(session, workspace),
            command: CanonicalId::now_v7(),
            conversation,
            workspace,
            prompt,
            profile: profile.map(|profile| {
                (
                    profile.profile_id().to_owned(),
                    hex::encode(profile.profile_digest()),
                )
            }),
        }
    }
    pub fn identity(&self) -> Result<CommandIdentity, String> {
        CommandIdentity::new(self.command, format!("tui-command:{}", self.command))
            .map_err(|error| error.to_string())
    }
    pub fn submit(&self) -> Result<SubmitTaskRunRequest, String> {
        let mut request = SubmitTaskRunRequest::new(
            self.identity()?,
            self.conversation,
            self.workspace,
            self.prompt.clone().ok_or("Missing submission prompt")?,
        )
        .map_err(|error| error.to_string())?;
        if let Some((id, digest)) = &self.profile {
            let bytes: [u8; 32] = hex::decode(digest)
                .map_err(|_| "Invalid pending profile")?
                .try_into()
                .map_err(|_| "Invalid pending profile")?;
            request = request
                .with_selected_profile(
                    runne_api::SelectedProviderProfile::new(id.clone(), bytes)
                        .map_err(|_| "Invalid pending profile")?,
                )
                .map_err(|error| error.to_string())?;
        }
        Ok(request)
    }
    pub fn witness(&self) -> Result<CommandReconciliationRequest, String> {
        if self.prompt.is_some() {
            CommandReconciliationRequest::submit_task_run_from_request(&self.submit()?)
                .map_err(|error| error.to_string())
        } else {
            Ok(CommandReconciliationRequest::create_conversation(
                self.identity()?,
                self.conversation,
                self.workspace,
            ))
        }
    }
}

pub(super) fn scope(session: &RuntimeSessionInfo, workspace: CanonicalId) -> String {
    let mut hash = Sha256::new();
    hash.update(b"runne:terminal-command-journal:v1\0");
    for field in [
        &session.profile_id,
        &session.schema_hash,
        &session.authority_id,
        &session.principal_id,
        &session.event_log_lineage_id,
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.update(workspace.to_string());
    hex::encode(hash.finalize())
}
