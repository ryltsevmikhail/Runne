#[cfg(test)]
use std::sync::{Arc, Mutex};

use super::{native, state};

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CleanupEvent {
    FieldCleared,
    FieldReleased,
    StateRemoved,
    SheetClosed,
}

#[cfg(test)]
#[derive(Clone)]
/// Structural observer: it receives lifecycle events, never credential bytes.
pub(super) struct CleanupObserver(Arc<Mutex<Vec<CleanupEvent>>>);

#[cfg(test)]
impl CleanupObserver {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn record(&self, event: CleanupEvent) {
        self.0.lock().expect("cleanup observer lock").push(event);
    }

    pub(super) fn events(&self) -> Vec<CleanupEvent> {
        self.0.lock().expect("cleanup observer lock").clone()
    }
}

pub(super) fn finish(id: u64) -> bool {
    let prompt = state::with_prompts(|prompts| {
        let prompt = prompts.get_mut(&id)?;
        prompt.clear_field();
        prompt.release_field();
        let prompt = prompts.remove(&id)?;
        #[cfg(test)]
        prompt.record_removed();
        Some(prompt)
    });
    let Some(prompt) = prompt else {
        return false;
    };
    prompt.close_sheet();
    true
}

pub(super) fn finish_unregistered(mut prompt: state::PromptUiState) {
    prompt.clear_field();
    prompt.release_field();
    prompt.close_sheet();
}

impl state::PromptUiState {
    fn clear_field(&mut self) {
        match self {
            Self::Native { field, .. } => {
                if let Some(field) = field.as_deref() {
                    native::clear_secure_field(field);
                }
            }
            #[cfg(test)]
            Self::Observed {
                observer,
                has_field,
            } => {
                if *has_field {
                    observer.record(CleanupEvent::FieldCleared);
                }
            }
        }
    }

    fn release_field(&mut self) {
        match self {
            Self::Native { field, .. } => {
                field.take();
            }
            #[cfg(test)]
            Self::Observed {
                observer,
                has_field,
            } => {
                if *has_field {
                    *has_field = false;
                    observer.record(CleanupEvent::FieldReleased);
                }
            }
        }
    }

    #[cfg(test)]
    fn record_removed(&self) {
        if let Self::Observed { observer, .. } = self {
            observer.record(CleanupEvent::StateRemoved);
        }
    }

    fn close_sheet(self) {
        match self {
            Self::Native { sheet, .. } => native::close_sheet(&sheet),
            #[cfg(test)]
            Self::Observed { observer, .. } => observer.record(CleanupEvent::SheetClosed),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};

    use runne_platform_desktop::{
        SecureCredentialMaterial, SecureCredentialPromptDisposition, SecureCredentialPromptError,
    };
    use zeroize::Zeroizing;

    use super::{CleanupEvent, CleanupObserver, finish, finish_unregistered};
    use crate::provider_credential_enrollment::host_prompt::OneShotPromptResult;

    use super::super::{PromptResult, finish_terminal, finish_timeout_on_main, state};

    const EXPECTED_CLEANUP: [CleanupEvent; 4] = [
        CleanupEvent::FieldCleared,
        CleanupEvent::FieldReleased,
        CleanupEvent::StateRemoved,
        CleanupEvent::SheetClosed,
    ];

    fn observed_prompt() -> (u64, CleanupObserver) {
        let id = state::allocate_id().expect("prompt id");
        let observer = CleanupObserver::new();
        let prompt = state::PromptUiState::observed(observer.clone(), true);
        assert!(state::insert(id, prompt).is_ok());
        (id, observer)
    }

    fn run_completion(result: PromptResult) -> PromptResult {
        let (id, observer) = observed_prompt();
        let winner = Arc::new(OneShotPromptResult::new());
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let (cleanup_sender, cleanup_receiver) = mpsc::channel();

        finish_terminal(id, &winner, &result_sender, &cleanup_sender, result);

        cleanup_receiver.recv().expect("cleanup acknowledgement");
        let result = result_receiver.recv().expect("terminal result");
        assert_eq!(observer.events(), EXPECTED_CLEANUP);
        result
    }

    #[test]
    fn submit_clears_field_before_removing_state() {
        let material = SecureCredentialMaterial::from_zeroizing(Zeroizing::new(vec![7]))
            .expect("bounded material");
        assert!(matches!(
            run_completion(Ok(SecureCredentialPromptDisposition::Submitted(material))),
            Ok(SecureCredentialPromptDisposition::Submitted(_))
        ));
    }

    #[test]
    fn cancel_clears_field_before_removing_state() {
        assert!(matches!(
            run_completion(Ok(SecureCredentialPromptDisposition::Cancelled)),
            Ok(SecureCredentialPromptDisposition::Cancelled)
        ));
    }

    #[test]
    fn invalid_response_clears_field_before_removing_state() {
        assert!(matches!(
            run_completion(Err(SecureCredentialPromptError::Unavailable)),
            Err(SecureCredentialPromptError::Unavailable)
        ));
    }

    #[test]
    fn timeout_clears_field_before_removing_state() {
        let (id, observer) = observed_prompt();
        let (cleanup_sender, cleanup_receiver) = mpsc::channel();

        finish_timeout_on_main(id, &cleanup_sender);

        cleanup_receiver.recv().expect("cleanup acknowledgement");
        assert_eq!(observer.events(), EXPECTED_CLEANUP);
    }

    #[test]
    fn repeated_cleanup_clears_and_releases_exactly_once() {
        let (id, observer) = observed_prompt();

        finish(id);
        finish(id);

        assert_eq!(observer.events(), EXPECTED_CLEANUP);
    }

    #[test]
    fn window_loss_cleans_any_retained_prompt_before_reporting_failure() {
        assert!(matches!(
            run_completion(Err(SecureCredentialPromptError::Unavailable)),
            Err(SecureCredentialPromptError::Unavailable)
        ));
    }

    #[test]
    fn scheduling_failure_cleanup_is_idempotent_without_prompt_state() {
        let id = state::allocate_id().expect("prompt id");

        assert!(!finish(id));
        assert!(!finish(id));
    }

    #[test]
    fn unregistered_prompt_clears_field_before_releasing_native_owners() {
        let observer = CleanupObserver::new();
        let prompt = state::PromptUiState::observed(observer.clone(), true);

        finish_unregistered(prompt);

        assert_eq!(
            observer.events(),
            [
                CleanupEvent::FieldCleared,
                CleanupEvent::FieldReleased,
                CleanupEvent::SheetClosed,
            ]
        );
    }

    #[test]
    fn insertion_failure_preserves_registered_state_and_cleans_candidate() {
        let (id, registered) = observed_prompt();
        let candidate = CleanupObserver::new();
        let candidate_state = state::PromptUiState::observed(candidate.clone(), true);

        let candidate_state = state::insert(id, candidate_state).expect_err("duplicate id");
        finish_unregistered(candidate_state);

        assert_eq!(registered.events(), []);
        assert_eq!(
            candidate.events(),
            [
                CleanupEvent::FieldCleared,
                CleanupEvent::FieldReleased,
                CleanupEvent::SheetClosed,
            ]
        );
        assert!(finish(id));
    }
}
