use std::sync::atomic::{AtomicU8, Ordering};
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

const SETUP_PENDING: u8 = 0;
const PROMPT_REGISTERED: u8 = 1;
const SETUP_CANCELLED: u8 = 2;

#[derive(Clone)]
pub(super) struct PromptTerminal {
    winner: Arc<OneShotPromptResult>,
    sender: mpsc::SyncSender<PromptResult>,
    lifecycle: Arc<AtomicU8>,
}

impl PromptTerminal {
    pub(super) fn new(
        winner: Arc<OneShotPromptResult>,
        sender: mpsc::SyncSender<PromptResult>,
    ) -> Self {
        Self {
            winner,
            sender,
            lifecycle: Arc::new(AtomicU8::new(SETUP_PENDING)),
        }
    }

    fn register(&self) -> bool {
        self.lifecycle
            .compare_exchange(
                SETUP_PENDING,
                PROMPT_REGISTERED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn cancel_pending(&self, result: PromptResult) -> bool {
        if self
            .lifecycle
            .compare_exchange(
                SETUP_PENDING,
                SETUP_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let claimed = self.winner.claim();
        self.publish_claimed(claimed, result);
        claimed
    }

    fn close_registration(&self) {
        let _ = self.lifecycle.compare_exchange(
            SETUP_PENDING,
            SETUP_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(super) fn finish_registered(&self, id: u64, result: PromptResult) {
        self.close_registration();
        let claimed = self.winner.claim();
        cleanup::finish(id);
        self.publish_claimed(claimed, result);
    }

    fn finish_unregistered(&self, prompt: PromptUiState, result: PromptResult) {
        self.close_registration();
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
        Ok(()) => {
            if !terminal.register() {
                cleanup::finish(id);
                return false;
            }
            true
        }
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
    terminal: &PromptTerminal,
    schedule_abort: impl FnOnce(MainTask),
) -> PromptResult {
    match receiver.recv_timeout(bound) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected | mpsc::RecvTimeoutError::Timeout) => {
            if terminal.cancel_pending(Err(SecureCredentialPromptError::Unavailable)) {
                return Err(SecureCredentialPromptError::Unavailable);
            }
            let fallback = terminal.clone();
            let (cleanup_sender, cleanup_receiver) = mpsc::sync_channel(1);
            schedule_abort(Box::new(move || {
                fallback.finish_registered(id, Err(SecureCredentialPromptError::Unavailable));
                let _ = cleanup_sender.send(());
            }));
            let _ = cleanup_receiver.recv();
            receiver
                .recv()
                .unwrap_or(Err(SecureCredentialPromptError::Unavailable))
        }
    }
}
