use std::sync::{Arc, mpsc};
use std::time::Duration;

use objc2_app_kit::{NSAlertFirstButtonReturn, NSAlertSecondButtonReturn};
use runne_platform_desktop::{
    CredentialPromptAction, SecureCredentialMaterial, SecureCredentialPromptDisposition,
    SecureCredentialPromptError,
};

use super::PromptResult;
use super::cleanup;
use super::state::{self, PromptUiState};
use crate::provider_credential_enrollment::host_prompt::OneShotPromptResult;

pub(super) type MainTask = Box<dyn FnOnce() + Send + 'static>;

#[derive(Clone)]
pub(super) struct PromptTerminal {
    winner: Arc<OneShotPromptResult>,
    sender: mpsc::SyncSender<PromptResult>,
}

impl PromptTerminal {
    pub(super) const fn new(
        winner: Arc<OneShotPromptResult>,
        sender: mpsc::SyncSender<PromptResult>,
    ) -> Self {
        Self { winner, sender }
    }

    pub(super) fn finish_registered(&self, id: u64, result: PromptResult) {
        let claimed = self.winner.claim();
        cleanup::finish(id);
        self.publish_claimed(claimed, result);
    }

    fn finish_unregistered(&self, prompt: PromptUiState, result: PromptResult) {
        let claimed = self.winner.claim();
        cleanup::finish_unregistered(prompt);
        self.publish_claimed(claimed, result);
    }

    fn publish_claimed(&self, claimed: bool, result: PromptResult) {
        if claimed {
            let _ = self.sender.send(result);
        }
    }
}

pub(super) fn register_or_finish(
    id: u64,
    prompt: PromptUiState,
    terminal: &PromptTerminal,
) -> bool {
    match state::insert(id, prompt) {
        Ok(()) => true,
        Err(candidate) => {
            terminal.finish_unregistered(candidate, Err(SecureCredentialPromptError::Unavailable));
            false
        }
    }
}

pub(super) fn resolve_response(
    response: isize,
    action: CredentialPromptAction,
    copy_secret: impl FnOnce() -> Result<SecureCredentialMaterial, SecureCredentialPromptError>,
) -> PromptResult {
    if response == NSAlertSecondButtonReturn {
        return Ok(SecureCredentialPromptDisposition::Cancelled);
    }
    if response != NSAlertFirstButtonReturn {
        return Err(SecureCredentialPromptError::Unavailable);
    }
    if action.requires_secret() {
        copy_secret().map(SecureCredentialPromptDisposition::Submitted)
    } else {
        Ok(SecureCredentialPromptDisposition::Confirmed)
    }
}

pub(super) fn complete_response(
    id: u64,
    response: isize,
    action: CredentialPromptAction,
    copy_secret: impl FnOnce() -> Result<SecureCredentialMaterial, SecureCredentialPromptError>,
    terminal: &PromptTerminal,
) {
    let result = resolve_response(response, action, copy_secret);
    terminal.finish_registered(id, result);
}

pub(super) fn arm_timeout(
    id: u64,
    timeout: Duration,
    terminal: &PromptTerminal,
    schedule: impl FnOnce(Duration, MainTask) -> Result<(), ()>,
) -> bool {
    let timeout_terminal = terminal.clone();
    let task = Box::new(move || {
        timeout_terminal.finish_registered(id, Ok(SecureCredentialPromptDisposition::TimedOut));
    });
    if schedule(timeout, task).is_ok() {
        return true;
    }
    terminal.finish_registered(id, Err(SecureCredentialPromptError::Unavailable));
    false
}

pub(super) fn wait_for_result(
    receiver: &mpsc::Receiver<PromptResult>,
    bound: Duration,
    id: u64,
    schedule_abort: impl FnOnce(MainTask) -> Result<(), ()>,
) -> PromptResult {
    match receiver.recv_timeout(bound) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected | mpsc::RecvTimeoutError::Timeout) => {
            let _ = schedule_abort(Box::new(move || {
                cleanup::finish(id);
            }));
            Err(SecureCredentialPromptError::Unavailable)
        }
    }
}
