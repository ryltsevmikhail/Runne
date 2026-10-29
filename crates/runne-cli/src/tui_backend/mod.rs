//! Runtime-client-only interactive orchestration. No local model/tool execution.
// Existing consent ports intentionally use local futures; this frontend joins them on one executor.
#![allow(clippy::future_not_send)]
mod activity;
mod approval;
mod approval_retry;
mod commands;
mod journal;
mod options;
pub mod owner;
mod pending;
mod projection;
#[cfg(test)]
mod pty_fixture;
mod quit;
mod recovery;

use crate::tui::{self, UiCommand, UiEvent, UiSnapshot};
pub use options::selected;
use owner::BackendOwner;
use runne_runtime_client::{ApprovalSummaryDto, CanonicalId, TaskRunSnapshot};
use std::{collections::HashMap, ffi::OsString, io::IsTerminal};
use tokio::sync::mpsc;

pub fn entry(arguments: Vec<OsString>) -> crate::ProcessOutcome {
    if arguments.iter().any(|arg| arg == "--help" || arg == "-h") {
        return outcome(Ok(options::HELP.to_owned()));
    }
    let options = match options::parse(arguments) {
        Ok(value) => value,
        Err(error) => return outcome(Err(error)),
    };
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return outcome(Err(
            "Interactive chat requires a terminal; use runne exec for non-interactive work".into(),
        ));
    }
    let result = tokio::runtime::Runtime::new()
        .map_err(|_| "Runtime unavailable".to_owned())
        .and_then(|runtime| {
            runtime.block_on(async {
                let (result, cleanup) =
                    runne_runtime_client::with_local_session_cleanup(Box::pin(async {
                        let owner =
                            Box::pin(owner::resolve(options.project, options.profile)).await?;
                        Box::pin(run_with_owner(owner, options.resume, options.picker)).await
                    }))
                    .await;
                cleanup.map_err(|_| "Local session cleanup failed".to_owned())?;
                result
            })
        });
    outcome(result.map(|()| String::new()))
}

fn outcome(result: Result<String, String>) -> crate::ProcessOutcome {
    match result {
        Ok(text) => crate::ProcessOutcome {
            stdout: if text.is_empty() {
                text
            } else {
                format!("{text}\n")
            },
            stderr: String::new(),
            exit_code: 0,
        },
        Err(error) => crate::ProcessOutcome {
            stdout: String::new(),
            stderr: format!("{error}\n"),
            exit_code: 1,
        },
    }
}

pub async fn run_with_owner(
    owner: BackendOwner,
    resume: Option<String>,
    picker: bool,
) -> Result<(), String> {
    let (commands, incoming) = mpsc::channel(32);
    let (events, snapshots) = mpsc::channel(16);
    let backend = serve(owner, resume, picker, incoming, events);
    let (frontend, ()) = tokio::join!(tui::run(commands, snapshots), backend);
    frontend.map_err(|error| error.to_string())
}

pub async fn serve(
    owner: BackendOwner,
    resume: Option<String>,
    picker: bool,
    mut commands: mpsc::Receiver<UiCommand>,
    events: mpsc::Sender<UiEvent>,
) {
    let mut state = Backend::new(owner);
    state.selected = resume.as_deref().and_then(|id| CanonicalId::parse(id).ok());
    if picker && resume.is_none() {
        let _ = events.send(UiEvent::ShowSessions).await;
    }
    let mut poll = tokio::time::interval(std::time::Duration::from_millis(700));
    loop {
        let mut sent_draft = None;
        let result = tokio::select! {
            command = commands.recv() => match command {
                None => break,
                Some(UiCommand::Quit) => {
                    match state.can_exit().await {
                        Ok(()) => { let _ = events.send(UiEvent::ExitAllowed).await; break; },
                        Err(error) => Err(error),
                    }
                },
                Some(command) => {
                    if let UiCommand::Send(text) = &command {
                        sent_draft = Some(text.clone());
                        state.submission_started = false;
                    }
                    let approval = match &command {
                        UiCommand::Approval { id, review_key, .. } => Some((id.clone(), review_key.clone())),
                        _ => None,
                    };
                    let result = state.command(command).await;
                    if let Some((id, review_key)) = approval {
                        let _ = events.send(UiEvent::ApprovalHandled { id, review_key }).await;
                    }
                    result
                },
            },
            _ = poll.tick() => state.refresh().await,
        };
        let restore_draft = result.is_err() && !state.submission_started;
        if let Err(error) = result {
            state.snapshot.status = "Connection/operation unavailable; no automatic replay".into();
            if events.send(UiEvent::Error(error)).await.is_err() {
                break;
            }
        }
        if let Some(draft) = sent_draft {
            let _ = events
                .send(UiEvent::SubmissionFinished {
                    rejected_draft: restore_draft.then_some(draft),
                })
                .await;
        }
        for draft in std::mem::take(&mut state.recovered_drafts)
            .into_iter()
            .rev()
        {
            let _ = events
                .send(UiEvent::SubmissionFinished {
                    rejected_draft: Some(draft),
                })
                .await;
        }
        if events
            .send(UiEvent::Snapshot(state.snapshot.clone()))
            .await
            .is_err()
        {
            break;
        }
    }
}

struct Backend {
    owner: BackendOwner,
    selected: Option<CanonicalId>,
    snapshot: UiSnapshot,
    runs: Vec<TaskRunSnapshot>,
    approvals: Vec<ApprovalSummaryDto>,
    titles: HashMap<CanonicalId, (String, String)>,
    submit_uncertain: bool,
    submission_started: bool,
    recovered_drafts: Vec<String>,
    registration_attempted: bool,
    journal: Option<journal::Journal>,
}
impl Backend {
    fn new(owner: BackendOwner) -> Self {
        Self {
            snapshot: UiSnapshot {
                project: owner.project_label.clone(),
                model: owner.selected_profile.as_ref().map_or_else(
                    || "runtime selected".into(),
                    |profile| profile.profile_id().to_owned(),
                ),
                status: "Connecting".into(),
                ..Default::default()
            },
            owner,
            selected: None,
            runs: vec![],
            approvals: vec![],
            titles: HashMap::new(),
            submit_uncertain: false,
            submission_started: false,
            recovered_drafts: Vec::new(),
            registration_attempted: false,
            journal: None,
        }
    }
}
