use serde::Serialize;

/// Safe renderer result of an intent request. It cannot identify or replay it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialIntentProjection {
    Unavailable,
}
