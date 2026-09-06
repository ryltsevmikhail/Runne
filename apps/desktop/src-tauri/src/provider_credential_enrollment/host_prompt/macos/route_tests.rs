use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use objc2_app_kit::{NSAlertFirstButtonReturn, NSAlertSecondButtonReturn, NSModalResponseAbort};
use runne_platform_desktop::{
    CredentialPromptAction, SecureCredentialMaterial, SecureCredentialPromptDisposition,
    SecureCredentialPromptError,
};
use zeroize::Zeroizing;

use super::cleanup::{self, CleanupEvent, CleanupObserver};
use super::routes::{self, MainTask, PromptTerminal};
use super::state::{self, PromptUiState};
use crate::provider_credential_enrollment::host_prompt::OneShotPromptResult;

const EXPECTED_CLEANUP: [CleanupEvent; 4] = [
    CleanupEvent::FieldCleared,
    CleanupEvent::FieldReleased,
    CleanupEvent::StateRemoved,
    CleanupEvent::SheetClosed,
];

fn terminal() -> (
    PromptTerminal,
    mpsc::Receiver<Result<SecureCredentialPromptDisposition, SecureCredentialPromptError>>,
) {
    let winner = Arc::new(OneShotPromptResult::new());
    let (sender, receiver) = mpsc::sync_channel(1);
    (PromptTerminal::new(winner, sender), receiver)
}

fn registered_prompt() -> (u64, CleanupObserver) {
    let id = state::allocate_id().expect("prompt id");
    let observer = CleanupObserver::new();
    let prompt = PromptUiState::observed(observer.clone(), true);
    assert!(state::insert(id, prompt).is_ok());
    (id, observer)
}

fn material() -> SecureCredentialMaterial {
    SecureCredentialMaterial::from_zeroizing(Zeroizing::new(vec![7])).expect("bounded material")
}

fn one_result(
    receiver: &mpsc::Receiver<
        Result<SecureCredentialPromptDisposition, SecureCredentialPromptError>,
    >,
) -> Result<SecureCredentialPromptDisposition, SecureCredentialPromptError> {
    let first = receiver.try_recv().expect("one terminal result");
    assert!(receiver.try_recv().is_err());
    first
}

fn assert_cleaned(id: u64, observer: &CleanupObserver) {
    assert_eq!(observer.events(), EXPECTED_CLEANUP);
    assert!(!state::contains(id));
}

#[test]
fn submit_callback_resolves_response_then_cleans_and_publishes_once() {
    let (id, observer) = registered_prompt();
    let (terminal, receiver) = terminal();

    routes::complete_response(
        id,
        NSAlertFirstButtonReturn,
        CredentialPromptAction::Pair,
        || Ok(material()),
        &terminal,
    );

    assert!(matches!(
        one_result(&receiver),
        Ok(SecureCredentialPromptDisposition::Submitted(_))
    ));
    assert_cleaned(id, &observer);
}

#[test]
fn cancel_callback_skips_secret_copy_then_cleans_and_publishes_once() {
    let (id, observer) = registered_prompt();
    let (terminal, receiver) = terminal();
    let copied = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let copied_by_callback = Arc::clone(&copied);

    routes::complete_response(
        id,
        NSAlertSecondButtonReturn,
        CredentialPromptAction::Pair,
        move || {
            copied_by_callback.store(true, std::sync::atomic::Ordering::Release);
            Ok(material())
        },
        &terminal,
    );

    assert!(matches!(
        one_result(&receiver),
        Ok(SecureCredentialPromptDisposition::Cancelled)
    ));
    assert!(!copied.load(std::sync::atomic::Ordering::Acquire));
    assert_cleaned(id, &observer);
}

#[test]
fn invalid_callback_skips_secret_copy_then_cleans_and_publishes_once() {
    let (id, observer) = registered_prompt();
    let (terminal, receiver) = terminal();

    routes::complete_response(
        id,
        9_999,
        CredentialPromptAction::Pair,
        || panic!("invalid response must not copy material"),
        &terminal,
    );

    assert!(matches!(
        one_result(&receiver),
        Err(SecureCredentialPromptError::Unavailable)
    ));
    assert_cleaned(id, &observer);
}

#[test]
fn insertion_failure_cleans_only_candidate_and_preserves_existing_prompt() {
    let (id, existing) = registered_prompt();
    let candidate = CleanupObserver::new();
    let candidate_state = PromptUiState::observed(candidate.clone(), true);
    let (terminal, receiver) = terminal();

    assert!(!routes::register_or_finish(id, candidate_state, &terminal));

    assert_eq!(existing.events(), []);
    assert!(state::contains(id));
    assert_eq!(
        candidate.events(),
        [
            CleanupEvent::FieldCleared,
            CleanupEvent::FieldReleased,
            CleanupEvent::SheetClosed,
        ]
    );
    assert!(matches!(
        one_result(&receiver),
        Err(SecureCredentialPromptError::Unavailable)
    ));
    assert!(cleanup::finish(id));
}

#[test]
fn timeout_scheduler_failure_cleans_registered_prompt_and_returns_once() {
    let (id, observer) = registered_prompt();
    let (terminal, receiver) = terminal();

    assert!(!routes::arm_timeout(
        id,
        Duration::from_secs(30),
        &terminal,
        |_, _| Err(())
    ));

    assert!(matches!(
        one_result(&receiver),
        Err(SecureCredentialPromptError::Unavailable)
    ));
    assert_cleaned(id, &observer);
}

#[test]
fn window_loss_cleans_registered_prompt_and_returns_once() {
    let (id, observer) = registered_prompt();
    let (terminal, receiver) = terminal();

    routes::complete_response(
        id,
        NSModalResponseAbort,
        CredentialPromptAction::Pair,
        || panic!("window loss must not copy material"),
        &terminal,
    );

    assert!(matches!(
        one_result(&receiver),
        Err(SecureCredentialPromptError::Unavailable)
    ));
    assert_cleaned(id, &observer);
}

#[test]
fn disconnected_result_route_enqueues_main_thread_cleanup_without_waiting() {
    let (id, observer) = registered_prompt();
    let (sender, receiver) = mpsc::sync_channel(1);
    drop(sender);

    let result = routes::wait_for_result(&receiver, Duration::from_millis(1), id, |task| {
        task();
        Ok(())
    });

    assert!(matches!(
        result,
        Err(SecureCredentialPromptError::Unavailable)
    ));
    assert_cleaned(id, &observer);
}

fn armed_timeout(id: u64, terminal: &PromptTerminal) -> Arc<Mutex<Option<MainTask>>> {
    let task = Arc::new(Mutex::new(None));
    let scheduled = Arc::clone(&task);
    assert!(routes::arm_timeout(
        id,
        Duration::from_secs(30),
        terminal,
        move |_, timeout| {
            *scheduled.lock().expect("timeout slot") = Some(timeout);
            Ok(())
        }
    ));
    task
}

fn run_timeout(task: &Arc<Mutex<Option<MainTask>>>) {
    task.lock()
        .expect("timeout slot")
        .take()
        .expect("armed timeout")();
}

#[test]
fn completion_wins_race_with_timeout_with_one_result_and_one_cleanup() {
    let (id, observer) = registered_prompt();
    let (terminal, receiver) = terminal();
    let timeout = armed_timeout(id, &terminal);

    routes::complete_response(
        id,
        NSAlertFirstButtonReturn,
        CredentialPromptAction::Pair,
        || Ok(material()),
        &terminal,
    );
    run_timeout(&timeout);

    assert!(matches!(
        one_result(&receiver),
        Ok(SecureCredentialPromptDisposition::Submitted(_))
    ));
    assert_cleaned(id, &observer);
}

#[test]
fn timeout_wins_race_with_completion_with_one_result_and_one_cleanup() {
    let (id, observer) = registered_prompt();
    let (terminal, receiver) = terminal();
    let timeout = armed_timeout(id, &terminal);

    run_timeout(&timeout);
    routes::complete_response(
        id,
        NSAlertFirstButtonReturn,
        CredentialPromptAction::Pair,
        || Ok(material()),
        &terminal,
    );

    assert!(matches!(
        one_result(&receiver),
        Ok(SecureCredentialPromptDisposition::TimedOut)
    ));
    assert_cleaned(id, &observer);
}

#[test]
fn reentrant_terminal_during_field_clear_cannot_replace_claimed_result() {
    let id = state::allocate_id().expect("prompt id");
    let observer = CleanupObserver::new();
    let (terminal, receiver) = terminal();
    let reentrant_terminal = terminal.clone();
    let prompt = PromptUiState::observed_reentrant(observer.clone(), move || {
        reentrant_terminal.finish_registered(id, Ok(SecureCredentialPromptDisposition::TimedOut));
    });
    assert!(state::insert(id, prompt).is_ok());
    routes::complete_response(
        id,
        NSAlertFirstButtonReturn,
        CredentialPromptAction::Pair,
        || Ok(material()),
        &terminal,
    );

    assert!(matches!(
        one_result(&receiver),
        Ok(SecureCredentialPromptDisposition::Submitted(_))
    ));
    assert_cleaned(id, &observer);
}
