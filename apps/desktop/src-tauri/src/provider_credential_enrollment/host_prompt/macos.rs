//! Main-thread `AppKit` credential prompt boundary.

use std::sync::{Arc, mpsc};
use std::time::Duration;

use block2::RcBlock;
use objc2::MainThreadMarker;
use objc2_app_kit::{
    NSAlert, NSAlertFirstButtonReturn, NSAlertSecondButtonReturn, NSModalResponseAbort,
    NSSecureTextField, NSWindow,
};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
use runne_platform_desktop::{
    CredentialPromptAction, CredentialPromptProvider, MAX_CREDENTIAL_BYTES,
    SecureCredentialMaterial, SecureCredentialPromptDisposition, SecureCredentialPromptError,
    SecureCredentialPromptPort, SecureCredentialPromptRequest,
};
use tauri::{AppHandle, Manager, WebviewWindow};

use super::OneShotPromptResult;

mod native;
mod state;

type PromptResult = Result<SecureCredentialPromptDisposition, SecureCredentialPromptError>;

/// Native prompt owner bound to one exact Tauri webview window.
pub struct MacOsHostCredentialPrompt {
    app: AppHandle,
    window: WebviewWindow,
    timeout: Duration,
}

impl MacOsHostCredentialPrompt {
    pub(crate) const MAX_TIMEOUT: Duration = Duration::from_secs(30);

    pub(crate) fn new(
        window: WebviewWindow,
        timeout: Duration,
    ) -> Result<Self, SecureCredentialPromptError> {
        if timeout.is_zero() || timeout > Self::MAX_TIMEOUT {
            return Err(SecureCredentialPromptError::Rejected);
        }
        let app = window.app_handle().clone();
        Ok(Self {
            app,
            window,
            timeout,
        })
    }
}

impl SecureCredentialPromptPort for MacOsHostCredentialPrompt {
    fn prompt(&mut self, request: SecureCredentialPromptRequest) -> PromptResult {
        if MainThreadMarker::new().is_some() {
            return Err(SecureCredentialPromptError::Unavailable);
        }
        let id = state::allocate_id().ok_or(SecureCredentialPromptError::Unavailable)?;
        let winner = Arc::new(OneShotPromptResult::new());
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let (cleanup_sender, cleanup_receiver) = mpsc::channel();
        schedule_sheet(
            &self.app,
            self.window.clone(),
            id,
            request,
            Arc::clone(&winner),
            result_sender,
            cleanup_sender.clone(),
        )?;
        match result_receiver.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(SecureCredentialPromptError::Unavailable)
            }
            Err(mpsc::RecvTimeoutError::Timeout) if winner.claim() => {
                request_timeout_cleanup(&self.app, id, cleanup_sender);
                cleanup_receiver
                    .recv()
                    .map_err(|_| SecureCredentialPromptError::Unavailable)?;
                Ok(SecureCredentialPromptDisposition::TimedOut)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => result_receiver
                .recv()
                .map_err(|_| SecureCredentialPromptError::Unavailable)?,
        }
    }
}

fn schedule_sheet(
    app: &AppHandle,
    window: WebviewWindow,
    id: u64,
    request: SecureCredentialPromptRequest,
    winner: Arc<OneShotPromptResult>,
    sender: mpsc::SyncSender<PromptResult>,
    cleanup: mpsc::Sender<()>,
) -> Result<(), SecureCredentialPromptError> {
    app.run_on_main_thread(move || {
        if winner.is_claimed() || !matches!(window.is_focused(), Ok(true)) {
            finish(
                &winner,
                &sender,
                Err(SecureCredentialPromptError::Unavailable),
            );
            return;
        }
        let Some(mtm) = MainThreadMarker::new() else {
            finish(
                &winner,
                &sender,
                Err(SecureCredentialPromptError::Unavailable),
            );
            return;
        };
        let Some(parent) = native::retain_tauri_window(mtm, &window) else {
            finish(
                &winner,
                &sender,
                Err(SecureCredentialPromptError::Unavailable),
            );
            return;
        };
        if parent.attachedSheet().is_some() {
            finish(
                &winner,
                &sender,
                Err(SecureCredentialPromptError::Unavailable),
            );
            return;
        }
        show_sheet(&parent, id, request, winner, sender, cleanup);
    })
    .map_err(|_| SecureCredentialPromptError::Unavailable)
}

fn show_sheet(
    parent: &NSWindow,
    id: u64,
    request: SecureCredentialPromptRequest,
    winner: Arc<OneShotPromptResult>,
    sender: mpsc::SyncSender<PromptResult>,
    cleanup: mpsc::Sender<()>,
) {
    let mtm = MainThreadMarker::new().expect("scheduled on the AppKit main thread");
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str("GOCODE provider credential"));
    alert.setInformativeText(&NSString::from_str(&prompt_description(request)));
    alert.addButtonWithTitle(&NSString::from_str("Continue"));
    alert.addButtonWithTitle(&NSString::from_str("Cancel"));

    let field = request.action().requires_secret().then(|| {
        let field = NSSecureTextField::initWithFrame(
            mtm.alloc(),
            NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(360.0, 24.0)),
        );
        alert.setAccessoryView(Some(&field));
        field
    });
    let sheet = alert.window();
    if let Some(field) = field.as_ref() {
        sheet.setInitialFirstResponder(Some(field));
    }
    if !state::insert(
        id,
        state::PromptUiState {
            sheet,
            field: field.clone(),
        },
    ) {
        if let Some(field) = field.as_deref() {
            clear_field(field);
        }
        finish(
            &winner,
            &sender,
            Err(SecureCredentialPromptError::Unavailable),
        );
        return;
    }

    let completion = RcBlock::new(move |response| {
        let result = completion_result(response, field.as_deref(), request.action());
        if let Some(field) = field.as_deref() {
            clear_field(field);
        }
        state::remove(id);
        let _ = cleanup.send(());
        finish(&winner, &sender, result);
    });
    alert.beginSheetModalForWindow_completionHandler(parent, Some(&completion));
}

pub(super) fn completion_result(
    response: isize,
    field: Option<&NSSecureTextField>,
    action: CredentialPromptAction,
) -> PromptResult {
    if response == NSAlertSecondButtonReturn {
        return Ok(SecureCredentialPromptDisposition::Cancelled);
    }
    if response != NSAlertFirstButtonReturn {
        return Err(SecureCredentialPromptError::Unavailable);
    }
    if action.requires_secret() {
        let field = field.ok_or(SecureCredentialPromptError::Unavailable)?;
        copy_secret(field).map(SecureCredentialPromptDisposition::Submitted)
    } else {
        Ok(SecureCredentialPromptDisposition::Confirmed)
    }
}

fn copy_secret(
    field: &NSSecureTextField,
) -> Result<SecureCredentialMaterial, SecureCredentialPromptError> {
    let bytes = native::copy_utf8(&field.stringValue(), MAX_CREDENTIAL_BYTES)
        .map_err(|()| SecureCredentialPromptError::Rejected)?;
    SecureCredentialMaterial::from_zeroizing(bytes)
}

fn clear_field(field: &NSSecureTextField) {
    field.setStringValue(&NSString::new());
}

fn finish(
    winner: &OneShotPromptResult,
    sender: &mpsc::SyncSender<PromptResult>,
    result: PromptResult,
) {
    if winner.claim() {
        let _ = sender.send(result);
    }
}

fn request_timeout_cleanup(app: &AppHandle, id: u64, cleanup: mpsc::Sender<()>) {
    let _ = app.run_on_main_thread(move || {
        if let Some(prompt) = state::remove(id) {
            if let Some(field) = prompt.field.as_deref() {
                clear_field(field);
            }
            if let Some(parent) = prompt.sheet.sheetParent() {
                parent.endSheet_returnCode(&prompt.sheet, NSModalResponseAbort);
            } else {
                prompt.sheet.orderOut(None);
            }
        }
        let _ = cleanup.send(());
    });
}

fn prompt_description(request: SecureCredentialPromptRequest) -> String {
    let provider = match request.provider() {
        CredentialPromptProvider::OpenAi => "OpenAI",
        CredentialPromptProvider::DeepSeek => "DeepSeek",
    };
    let instruction = match request.action() {
        CredentialPromptAction::Pair => "Enter the new credential to pair",
        CredentialPromptAction::Rotate => "Enter the replacement credential to rotate",
        CredentialPromptAction::Revoke => "Confirm credential revocation for",
        CredentialPromptAction::MigrateLegacy => "Confirm legacy credential migration for",
    };
    format!(
        "{instruction} {provider} revision {}.",
        request.expected_revision()
    )
}

#[cfg(test)]
mod native_tests {
    use objc2::rc::Retained;

    use super::*;

    #[test]
    fn window_bridge_requires_main_thread_authority_and_returns_retained_window() {
        let _: fn(MainThreadMarker, &WebviewWindow) -> Option<Retained<NSWindow>> =
            native::retain_tauri_window;
    }
}
