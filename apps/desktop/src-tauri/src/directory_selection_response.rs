use serde::Serialize;

use crate::DirectorySelectionRef;

/// Renderer-safe response from the host-owned native directory picker.
#[derive(Debug, Serialize)]
pub struct DirectorySelectionResponse {
    reference: DirectorySelectionRef,
}

impl DirectorySelectionResponse {
    #[must_use]
    pub const fn new(reference: DirectorySelectionRef) -> Self {
        Self { reference }
    }
}
