use serde::Serialize;

/// Safe renderer result of an intent request. It cannot identify or replay it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialIntentProjection {
    /// The native consent and daemon dispatch chain accepted the intent.
    Pending,
    /// The native prompt was dismissed by the user; nothing was dispatched.
    Cancelled,
    /// The trusted chain is unavailable; the renderer must fail closed.
    /// Reserved for host builds without the native macOS chain.
    #[cfg_attr(target_os = "macos", expect(dead_code))]
    Unavailable,
}
