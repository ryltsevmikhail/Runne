/// Profile construction failure for a provider-owned endpoint component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// A resource or deployment component was not a safe DNS/path component.
    #[error("responses profile component is invalid")]
    InvalidComponent,
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "the sibling profile module needs this private validation helper"
)]
pub(crate) fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}
