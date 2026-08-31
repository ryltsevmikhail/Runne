use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::issuer::ProducerError;

const MAX_INPUT_BYTES: u64 = 512 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMetadataDraft {
    pub schema_version: u32,
    pub artifact_path: PathBuf,
    pub artifact_url: String,
    pub product_id: String,
    pub version: String,
    pub current_version: String,
    pub platform: String,
    pub arch: String,
    pub release_candidate_sha256: String,
    pub min_os: String,
    pub profile_id: String,
    pub bundle_sha256: String,
    pub runtime_version: String,
    pub runtime_digest: String,
    pub channel: String,
    pub published_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub rollback_floor: String,
    pub root_version: u64,
    pub targets_version: u64,
    pub snapshot_version: u64,
    pub timestamp_version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePublicKeyManifest {
    pub schema_version: u32,
    pub root_a_id: String,
    pub root_a_hex: String,
    pub root_b_id: String,
    pub root_b_hex: String,
    pub root_c_id: String,
    pub root_c_hex: String,
    pub snapshot_id: String,
    pub snapshot_hex: String,
    pub timestamp_id: String,
    pub timestamp_hex: String,
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ProducerError> {
    let mut file = File::open(path).map_err(|_| ProducerError::Input)?;
    let metadata = file.metadata().map_err(|_| ProducerError::Input)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_INPUT_BYTES {
        return Err(ProducerError::Input);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ProducerError::Input)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| ProducerError::Input)?;
    serde_json::from_slice(&bytes).map_err(|_| ProducerError::Input)
}
