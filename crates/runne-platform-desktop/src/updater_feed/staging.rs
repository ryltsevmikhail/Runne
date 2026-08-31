use std::path::{Path, PathBuf};

use reqwest::Response;
use sha2::{Digest, Sha256};

use crate::{StagedUpdate, UpdateFeedError};

pub async fn bounded_body(
    mut response: Response,
    maximum: usize,
) -> Result<Vec<u8>, UpdateFeedError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(UpdateFeedError::MetadataTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = match response.chunk().await {
        Ok(chunk) => chunk,
        Err(_) => return Err(UpdateFeedError::Transport),
    } {
        if body.len().saturating_add(chunk.len()) > maximum {
            return Err(UpdateFeedError::MetadataTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub async fn stage_response(
    mut response: Response,
    destination: &Path,
    expected_size: u64,
    expected_digest: &str,
) -> Result<StagedUpdate, UpdateFeedError> {
    if std::fs::symlink_metadata(destination).is_ok() {
        return Err(UpdateFeedError::StageFailed);
    }
    let parent = destination.parent().ok_or(UpdateFeedError::StageFailed)?;
    std::fs::create_dir_all(parent).map_err(|_| UpdateFeedError::StageFailed)?;
    let mut temporary = PathBuf::from(destination);
    temporary.set_extension("staged.tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| UpdateFeedError::StageFailed)?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    while let Some(chunk) = if let Ok(chunk) = response.chunk().await {
        chunk
    } else {
        let _ = std::fs::remove_file(&temporary);
        return Err(UpdateFeedError::Transport);
    } {
        size = size.saturating_add(chunk.len() as u64);
        if size > expected_size {
            let _ = std::fs::remove_file(&temporary);
            return Err(UpdateFeedError::ArtifactTooLarge);
        }
        if std::io::Write::write_all(&mut file, &chunk).is_err() {
            let _ = std::fs::remove_file(&temporary);
            return Err(UpdateFeedError::StageFailed);
        }
        digest.update(&chunk);
    }
    if file.sync_all().is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(UpdateFeedError::StageFailed);
    }
    drop(file);
    if size != expected_size || hex::encode(digest.finalize()) != expected_digest {
        let _ = std::fs::remove_file(&temporary);
        return Err(UpdateFeedError::DigestMismatch);
    }
    if std::fs::symlink_metadata(destination).is_ok() {
        let _ = std::fs::remove_file(&temporary);
        return Err(UpdateFeedError::StageFailed);
    }
    std::fs::rename(&temporary, destination).map_err(|_| UpdateFeedError::StageFailed)?;
    Ok(StagedUpdate {
        path: destination.to_path_buf(),
        artifact_sha256: expected_digest.to_owned(),
    })
}
