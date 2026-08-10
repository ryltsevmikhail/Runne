//! Versioned binary codec marker for canonical Project and Workspace records.

use super::{StoreCodec, StoreCodecError};

/// Strict codec for opaque, bounded Project/Workspace receipt payloads.
pub struct ProjectWorkspaceReceiptCodec;

impl StoreCodec<Vec<u8>> for ProjectWorkspaceReceiptCodec {
    const CODEC_VERSION: u16 = 1;
    fn encode(&self, value: &Vec<u8>) -> Result<Vec<u8>, StoreCodecError> {
        if value.len() > 4096 {
            return Err(StoreCodecError::Oversized {
                field: "project_workspace_receipt",
                max: 4096,
                actual: value.len(),
            });
        }
        Ok(value.clone())
    }
    fn decode(&self, bytes: &[u8]) -> Result<Vec<u8>, StoreCodecError> {
        self.encode(&bytes.to_vec())
    }
}
