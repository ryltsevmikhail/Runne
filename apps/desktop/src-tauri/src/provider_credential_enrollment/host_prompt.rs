#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]
#[cfg(target_os = "macos")]
mod macos;

#[cfg(test)]
mod tests;

#[cfg(target_os = "macos")]
pub use macos::MacOsHostCredentialPrompt;

use std::sync::atomic::{AtomicBool, Ordering};

pub(super) struct OneShotPromptResult(AtomicBool);

impl OneShotPromptResult {
    pub(super) const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    pub(super) fn claim(&self) -> bool {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(super) fn is_claimed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
