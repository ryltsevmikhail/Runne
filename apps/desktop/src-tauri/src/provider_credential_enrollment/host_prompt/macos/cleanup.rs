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
    let Ok(field) = state::begin_cleanup(id) else {
        return false;
    };
    if let Some(field) = field {
        field.clear_and_release();
    }
    let Some(prompt) = state::remove_cleaning(id) else {
        return false;
    };
    #[cfg(test)]
    prompt.record_removed();
    prompt.close_sheet();
    true
}

pub(super) fn finish_unregistered(mut prompt: state::PromptUiState) {
    if let Ok(Some(field)) = prompt.begin_cleanup() {
        field.clear_and_release();
    }
    prompt.close_sheet();
}

impl state::PromptFieldOwner {
    fn clear_and_release(self) {
        match self {
            Self::Native(field) => native::clear_secure_field(&field),
            #[cfg(test)]
            Self::Observed { observer, on_clear } => {
                observer.record(CleanupEvent::FieldCleared);
                if let Some(on_clear) = on_clear {
                    on_clear();
                }
                observer.record(CleanupEvent::FieldReleased);
            }
        }
    }
}

impl state::PromptUiState {
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
    use super::super::state;
    use super::{CleanupEvent, CleanupObserver, finish};

    const EXPECTED_CLEANUP: [CleanupEvent; 4] = [
        CleanupEvent::FieldCleared,
        CleanupEvent::FieldReleased,
        CleanupEvent::StateRemoved,
        CleanupEvent::SheetClosed,
    ];

    #[test]
    fn repeated_cleanup_clears_and_releases_exactly_once() {
        let id = state::allocate_id().expect("prompt id");
        let observer = CleanupObserver::new();
        let prompt = state::PromptUiState::observed(observer.clone(), true);
        assert!(state::insert(id, prompt).is_ok());

        finish(id);
        finish(id);

        assert_eq!(observer.events(), EXPECTED_CLEANUP);
    }

    #[test]
    fn reentrant_cleanup_during_field_clear_is_idempotent() {
        let id = state::allocate_id().expect("prompt id");
        let observer = CleanupObserver::new();
        let prompt = state::PromptUiState::observed_reentrant(observer.clone(), move || {
            assert!(!finish(id));
        });
        assert!(state::insert(id, prompt).is_ok());

        assert!(finish(id));

        assert_eq!(observer.events(), EXPECTED_CLEANUP);
        assert!(!state::contains(id));
    }
}
