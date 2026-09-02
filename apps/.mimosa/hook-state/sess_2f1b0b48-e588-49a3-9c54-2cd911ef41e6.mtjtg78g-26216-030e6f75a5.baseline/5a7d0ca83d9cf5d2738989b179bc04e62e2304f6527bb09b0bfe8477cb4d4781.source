use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use objc2::rc::Retained;
use objc2_app_kit::{NSSecureTextField, NSWindow};

static NEXT_PROMPT_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static PROMPTS: RefCell<HashMap<u64, PromptUiState>> = RefCell::new(HashMap::new());
}

pub(super) struct PromptUiState {
    pub(super) sheet: Retained<NSWindow>,
    pub(super) field: Option<Retained<NSSecureTextField>>,
}

pub(super) fn allocate_id() -> Option<u64> {
    NEXT_PROMPT_ID
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .ok()
}

pub(super) fn insert(id: u64, state: PromptUiState) -> bool {
    PROMPTS.with_borrow_mut(|prompts| prompts.insert(id, state).is_none())
}

pub(super) fn remove(id: u64) -> Option<PromptUiState> {
    PROMPTS.with_borrow_mut(|prompts| prompts.remove(&id))
}
