//! Main-thread `AppKit` credential prompt boundary.

use std::sync::{Arc, mpsc};
use std::time::Duration;

use block2::RcBlock;
use objc2::MainThreadMarker;
use objc2_app_kit::{NSAlert, NSSecureTextField, NSWindow};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
use runne_platform_desktop::{
    CredentialPromptAction, CredentialPromptProvider, MAX_CREDENTIAL_BYTES,
    SecureCredentialMaterial, SecureCredentialPromptDisposition, SecureCredentialPromptError,
    SecureCredentialPromptPort, SecureCredentialPromptRequest,
};
use tauri::WebviewWindow;

use super::OneShotPromptResult;

mod cleanup;
mod native;
mod routes;
mod state;

#[cfg(test)]
mod route_tests;

type PromptResult = Result<SecureCredentialPromptDisposition, SecureCredentialPromptError>;

/// Native prompt owner bound to one exact Tauri webview window.
pub struct MacOsHostCredentialPrompt {
    window: WebviewWindow,
    timeout: Duration,
}

impl MacOsHostCredentialPrompt {
    pub(crate) const MAX_TIMEOUT: Duration = Duration::from_secs(30);
    const CLEANUP_GRACE: Duration = Duration::from_millis(250);

    pub(crate) fn new(
        window: WebviewWindow,
        timeout: Duration,
    ) -> Result<Self, SecureCredentialPromptError> {
        if timeout.is_zero() || timeout > Self::MAX_TIMEOUT {
            return Err(SecureCredentialPromptError::Rejected);
        }
        Ok(Self { window, timeout })
    }
}

impl SecureCredentialPromptPort for MacOsHostCredentialPrompt {
    fn prompt(&mut self, request: SecureCredentialPromptRequest) -> PromptResult {
        if MainThreadMarker::new().is_some() {
            return Err(SecureCredentialPromptError::Unavailable);
        }
        let id = state::allocate_id().ok_or(SecureCredentialPromptError::Unavailable)?;
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let terminal =
            routes::PromptTerminal::new(Arc::new(OneShotPromptResult::new()), result_sender);
        schedule_sheet(
            self.window.clone(),
            id,
            request,
            terminal.clone(),
            self.timeout,
        );
        routes::wait_for_result(
            &result_receiver,
            self.timeout + Self::CLEANUP_GRACE,
            id,
            &terminal,
            native::schedule_main,
        )
    }
}

fn schedule_sheet(
    window: WebviewWindow,
    id: u64,
    request: SecureCredentialPromptRequest,
    terminal: routes::PromptTerminal,
    timeout: Duration,
) {
    native::run_on_main_thread_sync(move || {
        if !matches!(window.is_focused(), Ok(true)) {
            terminal.finish_registered(id, Err(SecureCredentialPromptError::Unavailable));
            return;
        }
        let Some(mtm) = MainThreadMarker::new() else {
            terminal.finish_registered(id, Err(SecureCredentialPromptError::Unavailable));
            return;
        };
        let Some(parent) = native::retain_tauri_window(mtm, &window) else {
            terminal.finish_registered(id, Err(SecureCredentialPromptError::Unavailable));
            return;
        };
        if parent.attachedSheet().is_some() {
            terminal.finish_registered(id, Err(SecureCredentialPromptError::Unavailable));
            return;
        }
        show_sheet(&parent, id, request, terminal, timeout);
    });
}

fn show_sheet(
    parent: &NSWindow,
    id: u64,
    request: SecureCredentialPromptRequest,
    terminal: routes::PromptTerminal,
    timeout: Duration,
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
    let prompt = state::PromptUiState::native(sheet, field.clone());
    if !routes::register_or_finish(id, prompt, &terminal) {
        return;
    }
    if !routes::arm_timeout(id, timeout, &terminal, native::schedule_timeout) {
        return;
    }

    let completion = RcBlock::new(move |response| {
        routes::complete_response(
            id,
            response,
            request.action(),
            || {
                let field = field
                    .as_deref()
                    .ok_or(SecureCredentialPromptError::Unavailable)?;
                copy_secret(field)
            },
            &terminal,
        );
    });
    alert.beginSheetModalForWindow_completionHandler(parent, Some(&completion));
}

#[cfg(test)]
pub(super) fn completion_result(
    response: isize,
    field: Option<&NSSecureTextField>,
    action: CredentialPromptAction,
) -> PromptResult {
    routes::resolve_response(response, action, || {
        let field = field.ok_or(SecureCredentialPromptError::Unavailable)?;
        copy_secret(field)
    })
}

fn copy_secret(
    field: &NSSecureTextField,
) -> Result<SecureCredentialMaterial, SecureCredentialPromptError> {
    let bytes = native::copy_utf8(&field.stringValue(), MAX_CREDENTIAL_BYTES)
        .map_err(|()| SecureCredentialPromptError::Rejected)?;
    SecureCredentialMaterial::from_zeroizing(bytes)
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
