//! Presentation-only terminal client. Runtime state arrives through typed channels.
mod editor;
mod input;
mod render;
mod state;
#[cfg(test)]
mod submission_tests;
mod terminal;
#[cfg(test)]
mod tests;

use tokio::sync::mpsc::{Receiver, Sender};

/// One hidden-input credential handed from the terminal frontend to the
/// protected runtime owner. It never carries serialization or debug output.
pub type CredentialSlot = std::sync::Arc<
    std::sync::Mutex<
        Option<(
            crate::ProviderCredentialId,
            runne_secure_store::ProviderCredentialMaterial,
        )>,
    >,
>;

#[derive(Debug, PartialEq, Eq)]
pub enum UiCommand {
    Send(String),
    EnrollCredential {
        provider: crate::ProviderCredentialId,
    },
    NewSession,
    RegisterProject,
    SelectSession(String),
    Cancel,
    Approval {
        id: String,
        decision: bool,
        version: u64,
        review_key: String,
    },
    Refresh,
    Quit,
}

#[derive(Clone, Debug, Default)]
pub struct SessionEntry {
    pub id: String,
    pub title: String,
    pub updated: String,
}
#[derive(Clone, Debug, Default)]
pub struct ApprovalEntry {
    pub review_key: String,
    pub version: u64,
    pub id: String,
    pub title: String,
    pub detail: String,
}
#[derive(Clone, Debug, Default)]
pub struct UiSnapshot {
    pub project: String,
    pub session: String,
    pub model: String,
    pub status: String,
    pub active: bool,
    pub sessions: Vec<SessionEntry>,
    pub messages: Vec<String>,
    pub actions: Vec<String>,
    pub diff: String,
    pub approvals: Vec<ApprovalEntry>,
    pub credential_enrollment: Option<bool>,
}
#[derive(Debug)]
pub enum UiEvent {
    SubmissionFinished {
        rejected_draft: Option<String>,
    },
    ApprovalHandled {
        id: String,
        review_key: String,
    },
    ShowSessions,
    ExitAllowed,
    Snapshot(UiSnapshot),
    #[expect(
        dead_code,
        reason = "channel supports provisional streaming text; snapshots currently carry durable messages"
    )]
    Text(String),
    Status(String),
    Error(String),
}

pub async fn run(
    commands: Sender<UiCommand>,
    mut events: Receiver<UiEvent>,
    credential_slot: CredentialSlot,
) -> std::io::Result<()> {
    use crossterm::event::{self, Event};
    let _terminal = terminal::Terminal::enter()?;
    let mut state = state::State {
        credential_slot,
        ..state::State::default()
    };
    commands
        .try_send(UiCommand::Refresh)
        .map_err(|_| std::io::Error::other("runtime channel closed"))?;
    loop {
        for _ in 0..128 {
            match events.try_recv() {
                Ok(event) => state.event(event),
                Err(_) => break,
            }
        }
        if state.exit_allowed {
            break;
        }
        render::draw(&state)?;
        if events.is_closed() && events.is_empty() {
            break;
        }
        if event::poll(std::time::Duration::from_millis(30))? {
            let keep_running = match event::read()? {
                Event::Key(key) => match input::key(&mut state, key, &commands) {
                    Ok(keep_running) => keep_running,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        state.notice = error.to_string();
                        true
                    }
                    Err(error) => return Err(error),
                },
                Event::Paste(text) => {
                    if state.credential_prompt.is_some() {
                        state.push_secret(&text);
                    } else {
                        state.editor.paste(&text);
                    }
                    true
                }
                _ => true,
            };
            if !keep_running {
                break;
            }
        }
        tokio::task::yield_now().await;
    }
    Ok(())
}
