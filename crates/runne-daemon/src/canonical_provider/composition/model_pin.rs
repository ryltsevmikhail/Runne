//! Exact-model admission surface of the canonical provider composition
//! (D1.4b, 2026-09-28).

use super::DaemonCanonicalProviderService;

impl DaemonCanonicalProviderService {
    /// The provider model pinned by this composition; exact-model admission
    /// compares requested models against it.
    pub fn pinned_model_id(&self) -> &str {
        &self.model_id
    }
}
