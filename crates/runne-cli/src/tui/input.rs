use super::{
    UiCommand,
    state::{Panel, State},
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use runne_secure_store::ProviderCredentialMaterial;
use tokio::sync::mpsc::Sender;

pub(super) fn key(
    state: &mut State,
    key: KeyEvent,
    commands: &Sender<UiCommand>,
) -> std::io::Result<bool> {
    if key.kind == KeyEventKind::Release {
        return Ok(true);
    }
    if state.credential_prompt.is_some() {
        return Ok(credential_key(state, key));
    }
    let send = |command| send_command(commands, command);
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        if matches!(key.code, KeyCode::F(1..=5)) {
            state.scroll = 0;
        }
        match key.code {
            KeyCode::Char('c') if state.snapshot.active => {
                send(UiCommand::Cancel)?;
                state.notice = "Cancellation pending runtime confirmation".into();
            }
            KeyCode::Char('q') => {
                send(UiCommand::Quit)?;
                state.notice = "Waiting for runtime exit confirmation".into();
            }
            KeyCode::Char('n') => send(UiCommand::NewSession)?,
            KeyCode::Char('r') => send(UiCommand::Refresh)?,
            _ => {}
        }
        return Ok(true);
    }
    match key.code {
        KeyCode::F(1) => state.panel = Panel::Help,
        KeyCode::F(2) => {
            state.panel = Panel::Sessions;
            state.selection = 0;
        }
        KeyCode::F(3) => state.panel = Panel::Actions,
        KeyCode::F(4) => state.panel = Panel::Diff,
        KeyCode::F(5) => state.panel = Panel::Permissions,
        KeyCode::Esc => {
            state.panel = Panel::Chat;
            state.query.clear();
            state.scroll = 0;
        }
        KeyCode::PageUp | KeyCode::PageDown => scroll(state, key.code == KeyCode::PageDown),
        KeyCode::Up if state.panel == Panel::Sessions || state.panel == Panel::Permissions => {
            state.selection = state.selection.saturating_sub(1);
        }
        KeyCode::Down if state.panel == Panel::Sessions || state.panel == Panel::Permissions => {
            state.selection = state.selection.saturating_add(1).min(
                if state.panel == Panel::Sessions {
                    state.sessions().len()
                } else {
                    state.snapshot.approvals.len()
                }
                .saturating_sub(1),
            );
        }
        KeyCode::Char('y' | 'n') if state.panel == Panel::Permissions => {
            if let Some(approval) = state.snapshot.approvals.get(state.selection) {
                if state
                    .submitted_approvals
                    .contains(&(approval.id.clone(), approval.review_key.clone()))
                {
                    return Ok(true);
                }
                send(UiCommand::Approval {
                    id: approval.id.clone(),
                    version: approval.version,
                    review_key: approval.review_key.clone(),
                    decision: key.code == KeyCode::Char('y'),
                })?;
                state
                    .submitted_approvals
                    .insert((approval.id.clone(), approval.review_key.clone()));
                state.notice = "Decision submitted; waiting for runtime".into();
            }
        }
        KeyCode::Char(c) if state.panel == Panel::Sessions => {
            state.query.push(c);
            state.selection = 0;
        }
        KeyCode::Backspace if state.panel == Panel::Sessions => {
            state.query.pop();
            state.selection = 0;
        }
        KeyCode::Enter if state.panel == Panel::Sessions => {
            if let Some(session) = state.sessions().get(state.selection) {
                send(UiCommand::SelectSession(session.id.clone()))?;
                state.panel = Panel::Chat;
            }
        }
        KeyCode::Enter if key.modifiers.is_empty() => {
            let draft = state.editor.clone();
            if let Err(error) = submit(state, &send) {
                state.editor = draft;
                return Err(error);
            }
        }
        _ => state.editor.key(key),
    }
    Ok(true)
}

fn submit(
    state: &mut State,
    send: &impl Fn(UiCommand) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let text = state.editor.take();
    match text.trim() {
        "" => {}
        "/login" | "/login deepseek" => {
            begin_credential(state, crate::ProviderCredentialId::DeepSeek)?;
        }
        "/login openai" => begin_credential(state, crate::ProviderCredentialId::OpenAi)?,
        "/new" => send(UiCommand::NewSession)?,
        "/register" => send(UiCommand::RegisterProject)?,
        "/sessions" => {
            state.panel = Panel::Sessions;
            state.selection = 0;
        }
        "/diff" => state.panel = Panel::Diff,
        "/permissions" => {
            state.panel = Panel::Permissions;
            state.selection = 0;
        }
        "/help" => state.panel = Panel::Help,
        "/quit" => {
            send(UiCommand::Quit)?;
            state.notice = "Waiting for runtime exit confirmation".into();
        }
        _ => {
            if state.snapshot.active || state.submission_pending {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Task or submission pending; draft kept, wait or cancel before sending",
                ));
            }
            if text.len() > 64 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Restored draft exceeds 64 KiB; edit before sending",
                ));
            }
            send(UiCommand::Send(text))?;
            state.submission_pending = true;
            state.scroll = 0;
        }
    }
    Ok(())
}

fn send_command(commands: &Sender<UiCommand>, command: UiCommand) -> std::io::Result<()> {
    commands.try_send(command).map_err(|error| match error {
        tokio::sync::mpsc::error::TrySendError::Full(_) => std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "Runtime busy; draft kept, retry when ready",
        ),
        tokio::sync::mpsc::error::TrySendError::Closed(_) => {
            std::io::Error::other("runtime channel closed")
        }
    })
}

const fn scroll(state: &mut State, down: bool) {
    let from_top = matches!(
        state.panel,
        Panel::Sessions | Panel::Help | Panel::Permissions
    );
    state.scroll = if down == from_top {
        state.scroll.saturating_add(5)
    } else {
        state.scroll.saturating_sub(5)
    };
}

fn begin_credential(
    state: &mut State,
    provider: crate::ProviderCredentialId,
) -> std::io::Result<()> {
    if state.snapshot.active || state.submission_pending {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "Task or submission pending; finish or cancel it before entering a key",
        ));
    }
    state.secret.clear();
    state.credential_prompt = Some(provider);
    state.notice =
        "Enter the API key (input hidden) · Enter saves to Keychain · Esc cancels".into();
    Ok(())
}

/// Reports exactly the completed step: the key reached the login Keychain.
///
/// The TUI cannot run the credential enrollment lifecycle, so the provider
/// stays unactivated and dispatch keeps failing closed. The notice must not
/// imply readiness or a runtime restart that would not change that.
const CREDENTIAL_STORED_NOTICE: &str =
    "Key saved to Keychain · provider activation not performed · unavailable in the CLI";

fn credential_key(state: &mut State, key: KeyEvent) -> bool {
    credential_key_with(state, key, crate::store_provider_credential_material)
}

pub(super) fn credential_key_with(
    state: &mut State,
    key: KeyEvent,
    store: impl Fn(
        crate::ProviderCredentialId,
        &ProviderCredentialMaterial,
    ) -> Result<(), crate::CliError>,
) -> bool {
    if key.kind == KeyEventKind::Release {
        return true;
    }
    match key.code {
        KeyCode::Esc => state.cancel_credential(),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.cancel_credential();
        }
        KeyCode::Enter => {
            let Some(provider) = state.credential_prompt.take() else {
                return true;
            };
            let secret = std::mem::take(&mut state.secret);
            let Ok(material) = ProviderCredentialMaterial::new(secret.as_bytes().to_vec()) else {
                state.notice = "Error: key is empty or exceeds the credential bound".into();
                return true;
            };
            match store(provider, &material) {
                Ok(()) => {
                    state.notice = CREDENTIAL_STORED_NOTICE.into();
                }
                Err(error) => {
                    state.notice = format!("Error: {error}; the key was not saved");
                }
            }
        }
        KeyCode::Backspace => {
            state.secret.pop();
        }
        KeyCode::Char(character) if !character.is_control() => {
            let mut encoded = [0_u8; 4];
            state.push_secret(character.encode_utf8(&mut encoded));
        }
        _ => {}
    }
    true
}
