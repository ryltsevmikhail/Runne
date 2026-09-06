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
    },
    #[cfg(test)]
    Observed {
        observer: CleanupObserver,
        has_field: bool,
    },
}

impl PromptUiState {
    pub(super) const fn native(
        sheet: Retained<NSWindow>,
        field: Option<Retained<NSSecureTextField>>,
    ) -> Self {
        Self::Native { sheet, field }
    }

    #[cfg(test)]
    pub(super) const fn observed(observer: CleanupObserver, has_field: bool) -> Self {
        Self::Observed {
            observer,
            has_field,
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

pub(super) fn with_prompts<T>(operation: impl FnOnce(&mut HashMap<u64, PromptUiState>) -> T) -> T {
    PROMPTS.with_borrow_mut(operation)
}
