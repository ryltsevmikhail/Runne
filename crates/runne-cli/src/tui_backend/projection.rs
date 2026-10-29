use super::Backend;
use crate::tui::{ApprovalEntry, SessionEntry};
use runne_runtime_client::{CanonicalId, ConversationMessageRole, WorkspaceDiffLineKindDto};
use std::fmt::Write as _;

impl Backend {
    pub(super) async fn refresh(&mut self) -> Result<(), String> {
        self.owner.maintain().await?;
        let Some(workspace) = self.owner.workspace_id else {
            self.snapshot.status = self.owner.registration_status().into();
            return Ok(());
        };
        self.recover_pending().await?;
        self.runs = self
            .owner
            .client
            .list_task_runs()
            .await
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|run| run.workspace_id() == Some(workspace))
            .collect();
        self.project_sessions(workspace).await?;
        if let Some(id) = self.selected {
            self.snapshot.session = self
                .titles
                .get(&id)
                .map_or_else(|| "Session".into(), |entry| entry.0.clone());
            self.snapshot.messages = self
                .owner
                .client
                .list_messages(id)
                .await
                .map_err(|error| error.to_string())?
                .messages
                .into_iter()
                .map(|message| {
                    format!(
                        "{}: {}",
                        match message.role {
                            ConversationMessageRole::User => "You",
                            ConversationMessageRole::Assistant => "Assistant",
                        },
                        message.text
                    )
                })
                .collect();
        } else {
            self.snapshot.session = "Choose F2 or start a new session".into();
            self.snapshot.messages.clear();
        }
        let selected_runs: Vec<_> = self
            .runs
            .iter()
            .filter(|run| run.conversation_id() == self.selected)
            .collect();
        self.snapshot.active = selected_runs
            .iter()
            .any(|run| !crate::is_terminal_state(run.state()));
        self.snapshot.actions = selected_runs
            .iter()
            .map(|run| {
                format!(
                    "{} — {}",
                    crate::task_state_name(run.state()),
                    crate::terminal_result_text(run.terminal_result())
                )
            })
            .collect();
        self.snapshot.status = if self.submit_uncertain {
            "Submission uncertain; reconciliation required".into()
        } else {
            selected_runs.last().map_or_else(
                || "Ready — F1 help".into(),
                |run| crate::task_state_name(run.state()).into(),
            )
        };
        self.project_activity().await;
        self.project_approvals().await;
        self.project_diff(workspace).await;
        Ok(())
    }

    async fn project_sessions(&mut self, workspace: CanonicalId) -> Result<(), String> {
        self.snapshot.sessions.clear();
        let mut after = None;
        loop {
            let page = self
                .owner
                .client
                .list_conversations(workspace, 100, after)
                .await
                .map_err(|error| error.to_string())?;
            for item in page.items {
                self.titles.insert(
                    item.conversation_id,
                    (item.title.clone(), timestamp(item.updated_at)),
                );
                self.snapshot.sessions.push(SessionEntry {
                    id: item.conversation_id.to_string(),
                    title: item.title,
                    updated: timestamp(item.updated_at),
                });
            }
            after = page.next_after;
            if after.is_none() {
                break;
            }
            if self.snapshot.sessions.len() >= 2000 {
                return Err(
                    "Session list exceeds 2000 display entries; narrow project scope".into(),
                );
            }
        }
        if let Some(selected) = self.selected
            && !self
                .snapshot
                .sessions
                .iter()
                .any(|entry| entry.id == selected.to_string())
        {
            return Err("Requested session is not in the admitted project".into());
        }
        Ok(())
    }

    async fn project_approvals(&mut self) {
        match self.owner.client.list_pending_approvals().await {
            Ok(approvals) => {
                self.approvals = approvals
                    .into_iter()
                    .filter(|approval| {
                        self.runs.iter().any(|run| {
                            run.task_run_id() == approval.task_run_id()
                                && run.conversation_id() == self.selected
                        })
                    })
                    .collect();
                self.snapshot.approvals = self
                    .approvals
                    .iter()
                    .map(|approval| ApprovalEntry {
                        version: approval.request_version(),
                        review_key: super::approval::review_key(
                            approval,
                            self.owner.client.session_info(),
                        ),
                        id: approval.approval_id().to_string(),
                        title: format!("{} — {}", approval.action(), approval.resource()),
                        detail: format!(
                            "{}\nVersion {} · policy {} · expires {}",
                            approval.risk_summary(),
                            approval.request_version(),
                            approval.policy_revision(),
                            timestamp(u64::try_from(approval.expires_at()).unwrap_or(0))
                        ),
                    })
                    .collect();
            }
            Err(error) => {
                self.approvals.clear();
                self.snapshot.approvals.clear();
                self.snapshot
                    .actions
                    .push(format!("Approval visibility unavailable: {error}"));
            }
        }
    }

    async fn project_diff(&mut self, workspace: CanonicalId) {
        let changes = match self
            .owner
            .client
            .list_workspace_changes(workspace, 20)
            .await
        {
            Ok(changes) => changes,
            Err(error) => {
                self.snapshot.diff = diff_unavailable(&error);
                return;
            }
        };
        let mut text = String::new();
        for entry in changes.entries() {
            let diff = match self
                .owner
                .client
                .read_workspace_diff(workspace, entry.path())
                .await
            {
                Ok(diff) => diff,
                Err(error) => {
                    let _ = writeln!(text, "--- {}\n[entry unavailable: {error}]", entry.path());
                    continue;
                }
            };
            let _ = writeln!(text, "--- {}\n+++ {}", diff.path(), diff.path());
            for hunk in diff.hunks() {
                let _ = writeln!(
                    text,
                    "@@ -{},{} +{},{} @@",
                    hunk.old_start(),
                    hunk.old_lines(),
                    hunk.new_start(),
                    hunk.new_lines()
                );
                for line in hunk.lines() {
                    text.push(match line.kind() {
                        WorkspaceDiffLineKindDto::Context => ' ',
                        WorkspaceDiffLineKindDto::Added => '+',
                        WorkspaceDiffLineKindDto::Removed => '-',
                    });
                    text.push_str(line.text());
                    text.push('\n');
                }
            }
            if diff.truncated() {
                text.push_str("[runtime diff truncated]\n");
            }
            if text.len() > 65536 {
                text.push_str("[display limit reached]\n");
                break;
            }
        }
        self.snapshot.diff = text;
    }
}

/// Distinguishes a missing recorded baseline from a genuine runtime failure.
///
/// The recorded-change view keeps an explicit unverified baseline when the
/// workspace root could not be pre-read at admission (bounded capture), so the
/// diff API answers `not_found` instead of pretending the runtime is down.
fn diff_unavailable(error: &runne_runtime_client::RuntimeApiError) -> String {
    if error.kind() == runne_runtime_client::RuntimeApiErrorKind::NotFound {
        "Diff unavailable: this workspace has no captured change baseline".into()
    } else {
        format!("Diff unavailable: {error}")
    }
}

fn timestamp(millis: u64) -> String {
    i64::try_from(millis)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map_or_else(
            || "Unknown time".into(),
            |date| date.format("%Y-%m-%d %H:%M").to_string(),
        )
}
