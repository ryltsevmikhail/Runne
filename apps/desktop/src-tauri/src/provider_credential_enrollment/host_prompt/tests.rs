use super::OneShotPromptResult;

#[cfg(target_os = "macos")]
use objc2_app_kit::{NSAlertFirstButtonReturn, NSAlertSecondButtonReturn};
#[cfg(target_os = "macos")]
use runne_platform_desktop::{
    CredentialPromptAction, CredentialPromptProvider, SecureCredentialPromptDisposition,
    SecureCredentialPromptError,
};

#[test]
fn one_shot_allows_exactly_one_sheet_or_timeout_winner() {
    let result = OneShotPromptResult::new();
    assert!(result.claim());
    assert!(!result.claim());
}

#[cfg(target_os = "macos")]
#[test]
fn confirmation_actions_never_require_a_secret_field() {
    use super::macos::completion_result;

    assert!(matches!(
        completion_result(
            NSAlertFirstButtonReturn,
            None,
            CredentialPromptProvider::OpenAi,
            CredentialPromptAction::Revoke
        ),
        Ok(SecureCredentialPromptDisposition::Confirmed)
    ));
    assert!(matches!(
        completion_result(
            NSAlertSecondButtonReturn,
            None,
            CredentialPromptProvider::OpenAi,
            CredentialPromptAction::MigrateLegacy
        ),
        Ok(SecureCredentialPromptDisposition::Cancelled)
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn secret_actions_fail_closed_without_a_secure_field() {
    assert!(matches!(
        super::macos::completion_result(
            NSAlertFirstButtonReturn,
            None,
            CredentialPromptProvider::OpenAi,
            CredentialPromptAction::Pair
        ),
        Err(SecureCredentialPromptError::Unavailable)
    ));
}
