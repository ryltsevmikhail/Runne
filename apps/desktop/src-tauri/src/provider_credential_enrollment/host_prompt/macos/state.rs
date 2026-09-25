use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::atomic::{AtomicU64, Ordering};

use objc2::rc::Retained;
use objc2_app_kit::{NSSecureTextField, NSWindow};

#[cfg(test)]
use super::cleanup::CleanupObserver;

static NEXT_PROMPT_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static PROMPTS: RefCell<HashMap<u64, PromptUiState>> = RefCell::new(HashMap::new());
}

pub(super) enum PromptUiState {
    Native {
        sheet: Retained<NSWindow>,
        field: Option<Retained<NSSecureTextField>>,
        phase: PromptPhase,
    },
    #[cfg(test)]
    Observed {
        observer: CleanupObserver,
        has_field: bool,
        phase: PromptPhase,
        on_clear: Option<Box<dyn FnOnce()>>,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum PromptPhase {
    Active,
    Cleaning,
}

pub(super) enum PromptFieldOwner {
    Native(Retained<NSSecureTextField>),
    #[cfg(test)]
    Observed {
        observer: CleanupObserver,
        on_clear: Option<Box<dyn FnOnce()>>,
    },
}

impl PromptUiState {
    pub(super) const fn native(
        sheet: Retained<NSWindow>,
        field: Option<Retained<NSSecureTextField>>,
    ) -> Self {
        Self::Native {
            sheet,
            field,
            phase: PromptPhase::Active,
        }
    }

    #[cfg(test)]
    pub(super) const fn observed(observer: CleanupObserver, has_field: bool) -> Self {
        Self::Observed {
            observer,
            has_field,
            phase: PromptPhase::Active,
            on_clear: None,
        }
    }

    #[cfg(test)]
    pub(super) fn observed_reentrant(
        observer: CleanupObserver,
        on_clear: impl FnOnce() + 'static,
    ) -> Self {
        Self::Observed {
            observer,
            has_field: true,
            phase: PromptPhase::Active,
            on_clear: Some(Box::new(on_clear)),
        }
    }

    pub(super) fn begin_cleanup(&mut self) -> Result<Option<PromptFieldOwner>, ()> {
        match self {
            Self::Native { field, phase, .. } => {
                if *phase == PromptPhase::Cleaning {
                    return Err(());
                }
                *phase = PromptPhase::Cleaning;
                Ok(field.take().map(PromptFieldOwner::Native))
            }
            #[cfg(test)]
            Self::Observed {
                observer,
                has_field,
                phase,
                on_clear,
            } => {
                if *phase == PromptPhase::Cleaning {
                    return Err(());
                }
                *phase = PromptPhase::Cleaning;
                Ok(has_field.then(|| PromptFieldOwner::Observed {
                    observer: observer.clone(),
                    on_clear: on_clear.take(),
                }))
            }
        }
    }

    fn is_cleaning(&self) -> bool {
        match self {
            Self::Native { phase, .. } => *phase == PromptPhase::Cleaning,
            #[cfg(test)]
            Self::Observed { phase, .. } => *phase == PromptPhase::Cleaning,
        }
    }
}

pub(super) fn allocate_id() -> Option<u64> {
    NEXT_PROMPT_ID
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .ok()
}

pub(super) fn insert(id: u64, state: PromptUiState) -> Result<(), PromptUiState> {
    PROMPTS.with_borrow_mut(|prompts| match prompts.entry(id) {
        Entry::Vacant(entry) => {
            entry.insert(state);
            Ok(())
        }
        Entry::Occupied(_) => Err(state),
    })
}

pub(super) fn begin_cleanup(id: u64) -> Result<Option<PromptFieldOwner>, ()> {
    PROMPTS.with_borrow_mut(|prompts| prompts.get_mut(&id).ok_or(())?.begin_cleanup())
}

pub(super) fn remove_cleaning(id: u64) -> Option<PromptUiState> {
    PROMPTS.with_borrow_mut(|prompts| {
        if !prompts.get(&id).is_some_and(PromptUiState::is_cleaning) {
            return None;
        }
        prompts.remove(&id)
    })
}

#[cfg(test)]
pub(super) fn contains(id: u64) -> bool {
    PROMPTS.with_borrow(|prompts| prompts.contains_key(&id))
}
