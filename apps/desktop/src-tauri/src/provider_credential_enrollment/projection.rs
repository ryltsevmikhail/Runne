#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]
use serde::Serialize;

/// Safe renderer result of an intent request. It cannot identify or replay it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialIntentProjection {
    /// Terminal safe readback completed and the exact writer was reaped.
    Completed,
    /// The native prompt was dismissed by the user; nothing was dispatched.
    Cancelled,
    /// The trusted chain is unavailable; the renderer must fail closed.
    /// Reserved for host builds without the native macOS chain.
    #[cfg_attr(target_os = "macos", expect(dead_code))]
    Unavailable,
}
