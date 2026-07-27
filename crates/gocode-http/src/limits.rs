//! HTTP request limits configuration for replay and other endpoints.
//!
//! Provides `LimitsConfig` with sensible defaults for maximum body
//! size, page size, and replay read-page limits.

use serde::{Deserialize, Serialize};

/// HTTP request limits configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LimitsConfig {
    /// Maximum request body size in bytes.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    /// Maximum page size for replay read_page.
    #[serde(default = "default_max_page_size")]
    pub max_page_size: usize,
    /// Default page size.
    #[serde(default = "default_page_size")]
    pub default_page_size: usize,
}

fn default_max_body_size() -> usize {
    1_048_576
} // 1 MB
fn default_max_page_size() -> usize {
    1_000
}
fn default_page_size() -> usize {
    100
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_size: default_max_body_size(),
            max_page_size: default_max_page_size(),
            default_page_size: default_page_size(),
        }
    }
}
