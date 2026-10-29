use super::Backend;
use crate::tui::UiCommand;
use runne_runtime_client::{
    CancelTaskRunRequest, CanonicalId, CommandIdentity, ConversationContextScope,
    CreateConversationRequest,
};

fn identity() -> Result<CommandIdentity, String> {
    let id = CanonicalId::now_v7();
    CommandIdentity::new(id, id.to_string()).map_err(|error| error.to_string())
}

impl Backend {
    pub(super) async fn command(&mut self, command: UiCommand) -> Result<(), String> {
        match command {
            UiCommand::Send(text) => self.send(text).await?,
            UiCommand::NewSession => self.create().await?,
            UiCommand::RegisterProject => {
                if self.registration_attempted && !self.owner.registration_retry_safe() {
                    return Err(
                        "Registration already attempted; reconcile its outcome before retrying"
                            .into(),
                    );
                }
                self.registration_attempted = true;
                self.owner.register_project().await?;
            }
            UiCommand::SelectSession(id) => {
                let id = CanonicalId::parse(&id).map_err(|error| error.to_string())?;
                if !self
                    .snapshot
                    .sessions
                    .iter()
                    .any(|entry| entry.id == id.to_string())
                {
                    return Err("Session does not belong to the admitted project".into());
                }
                self.selected = Some(id);
            }
            UiCommand::Cancel => {
                if let Some(task) = self.runs.iter().rev().find(|run| {
                    run.conversation_id() == self.selected && !crate::is_terminal_state(run.state())
                }) {
                    self.owner
                        .client
                        .cancel_task_run(CancelTaskRunRequest::new(
                            identity()?,
                            task.task_run_id(),
                            task.stream_version(),
                        ))
                        .await
                        .map_err(|error| error.to_string())?;
                    self.snapshot.status = "Cancellation pending runtime confirmation".into();
                }
            }
            UiCommand::Approval {
                id,
                decision,
                version,
                review_key,
            } => self.approve(id, decision, version, review_key).await?,
            UiCommand::RestartRuntime => {
                self.owner.restart().await?;
                self.runs.clear();
                self.approvals.clear();
                self.titles.clear();
                self.selected = None;
                self.snapshot.status = "Runtime restarted after credential enrollment".into();
            }
            UiCommand::Refresh | UiCommand::Quit => {}
        }
        self.refresh().await
    }

    async fn create(&mut self) -> Result<(), String> {
        let workspace = self.owner.workspace_id.ok_or("Project registration requires the protected runtime owner; this connection cannot admit a root")?;
        self.recover_pending().await?;
        let id = CanonicalId::now_v7();
        let pending = super::pending::Pending::new(
            self.owner.client.session_info(),
            workspace,
            id,
            None,
            None,
        );
        let request = CreateConversationRequest::new(
            pending.identity()?,
            id,
            workspace,
            ConversationContextScope::Workspace,
        );
        self.journal()?.save(&pending)?;
        self.submit_uncertain = true;
        let created = self
            .owner
            .client
            .create_conversation(request)
            .await
            .map_err(|error| format!("Session creation requires reconciliation: {error}"))?;
        self.journal()?.resolved(&pending)?;
        self.submit_uncertain = false;
        self.selected = Some(created.conversation_id);
        self.titles.insert(
            created.conversation_id,
            ("New session".into(), created.committed_at.to_string()),
        );
        Ok(())
    }

    async fn send(&mut self, text: String) -> Result<(), String> {
        if self.owner.workspace_id.is_some() {
            self.recover_pending().await?;
        }
        if self.submit_uncertain {
            return Err("Previous submission outcome is uncertain. Reconcile in runtime before submitting again.".into());
        }
        let workspace = self.owner.workspace_id.ok_or(
            "Project root is not admitted. Complete protected project registration before sending.",
        )?;
        self.refresh().await?;
        if self.snapshot.active {
            return Err(
                "A task is still active in this session; wait or cancel it before sending".into(),
            );
        }
        if self.selected.is_none() {
            self.create().await?;
        }
        let conversation = self.selected.ok_or("No session selected")?;
        let pending = super::pending::Pending::new(
            self.owner.client.session_info(),
            workspace,
            conversation,
            Some(text),
            self.owner.selected_profile.as_ref(),
        );
        let request = pending.submit()?;
        self.journal()?.save(&pending)?;
        self.submit_uncertain = true;
        self.submission_started = true;
        let acknowledgement = self
            .owner
            .client
            .submit_task_run(request)
            .await
            .map_err(|error| format!("Submission outcome uncertain; do not resend: {error}"))?;
        self.journal()?.resolved(&pending)?;
        self.submit_uncertain = false;
        self.snapshot.status = "Submitted; waiting for runtime".into();
        self.runs.push(
            self.owner
                .client
                .get_task_run(acknowledgement.task_run_id())
                .await
                .map_err(|error| error.to_string())?,
        );
        Ok(())
    }

    async fn approve(
        &self,
        id: String,
        decision: bool,
        version: u64,
        review_key: String,
    ) -> Result<(), String> {
        let approval = self
            .approvals
            .iter()
            .find(|approval| approval.approval_id().to_string() == id)
            .ok_or("Approval is no longer available")?;
        if approval.request_version() != version {
            return Err("Approval changed after display; refresh before deciding".into());
        }
        super::approval::decide(&self.owner.client, approval.clone(), &review_key, decision).await
    }
}
