//! Bounded HTTPS metadata and artifact transport for the native updater.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::redundant_pub_crate)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::{Client, Response, Url, redirect::Policy};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    StagedUpdate, UpdateMetadataV2, UpdateTargetV2Binding, UpdateTrustError, UpdateTrustJournal,
    UpdateTrustRootV2, UpdateV2VerificationError, VerifiedUpdateV2, verify_update_v2,
};

const MAX_METADATA_BYTES: usize = 512 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum UpdateFeedError {
    #[error("updater endpoint is invalid")]
    InvalidUrl,
    #[error("updater transport is unavailable")]
    Transport,
    #[error("updater endpoint returned an unexpected response")]
    HttpStatus,
    #[error("updater metadata exceeds its bound")]
    MetadataTooLarge,
    #[error("updater metadata is invalid")]
    InvalidMetadata,
    #[error("updater metadata verification failed")]
    Verification(#[source] UpdateV2VerificationError),
    #[error("updater trust floor rejected metadata")]
    Trust(#[source] UpdateTrustError),
    #[error("updater artifact exceeds its bound")]
    ArtifactTooLarge,
    #[error("updater artifact digest does not match metadata")]
    DigestMismatch,
    #[error("updater artifact could not be staged")]
    StageFailed,
}

/// Native-only updater transport. URLs and response bytes never cross IPC.
#[derive(Clone)]
pub struct UpdateFeedClient {
    client: Client,
}

impl UpdateFeedClient {
    /// Builds a TLS-only client with no redirects and bounded request time.
    pub fn new() -> Result<Self, UpdateFeedError> {
        Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_mins(1))
            .build()
            .map(|client| Self { client })
            .map_err(|_| UpdateFeedError::Transport)
    }

    /// Fetches strict signed metadata; cryptographic verification is separate.
    pub async fn fetch_metadata(
        &self,
        endpoint: &str,
    ) -> Result<UpdateMetadataV2, UpdateFeedError> {
        let url = parse_https_url(endpoint)?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| UpdateFeedError::Transport)?;
        if !response.status().is_success() {
            return Err(UpdateFeedError::HttpStatus);
        }
        let bytes = bounded_body(response, MAX_METADATA_BYTES).await?;
        serde_json::from_slice(&bytes).map_err(|_| UpdateFeedError::InvalidMetadata)
    }

    /// Fetches and verifies one target against the native profile binding.
    pub async fn check(
        &self,
        endpoint: &str,
        trust: &UpdateTrustRootV2,
        binding: &UpdateTargetV2Binding<'_>,
        now_unix_seconds: u64,
        current_version: &str,
        rollback_floor: &str,
    ) -> Result<VerifiedUpdateV2, UpdateFeedError> {
        let metadata = self.fetch_metadata(endpoint).await?;
        verify_update_v2(
            &metadata,
            trust,
            binding,
            now_unix_seconds,
            current_version,
            rollback_floor,
        )
        .map_err(UpdateFeedError::Verification)
    }

    /// Checks metadata and advances the native monotonic metadata floor.
    #[allow(clippy::too_many_arguments)]
    pub async fn check_with_trust_journal(
        &self,
        endpoint: &str,
        trust: &UpdateTrustRootV2,
        trust_journal: &UpdateTrustJournal,
        binding: &UpdateTargetV2Binding<'_>,
        now_unix_seconds: u64,
        current_version: &str,
        rollback_floor: &str,
    ) -> Result<VerifiedUpdateV2, UpdateFeedError> {
        let metadata = self.fetch_metadata(endpoint).await?;
        let verified = verify_update_v2(
            &metadata,
            trust,
            binding,
            now_unix_seconds,
            current_version,
            rollback_floor,
        )
        .map_err(UpdateFeedError::Verification)?;
        if trust_journal
            .read()
            .map_err(UpdateFeedError::Trust)?
            .is_none()
        {
            trust_journal
                .initialize(current_version, rollback_floor)
                .map_err(UpdateFeedError::Trust)?;
        }
        trust_journal
            .accept_metadata(
                metadata.root.version,
                metadata.snapshot.version,
                &verified.target().version,
            )
            .map_err(UpdateFeedError::Trust)?;
        Ok(verified)
    }

    /// Streams one already-verified target to a native staging path.
    pub async fn download_and_stage(
        &self,
        update: &VerifiedUpdateV2,
        destination: &Path,
    ) -> Result<StagedUpdate, UpdateFeedError> {
        let target = update.target();
        if target.artifact_size == 0 || target.artifact_size > MAX_ARTIFACT_BYTES {
            return Err(UpdateFeedError::ArtifactTooLarge);
        }
        let url = parse_https_url(&target.artifact_url)?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| UpdateFeedError::Transport)?;
        if !response.status().is_success() {
            return Err(UpdateFeedError::HttpStatus);
        }
        if response
            .content_length()
            .is_some_and(|length| length != target.artifact_size)
        {
            return Err(UpdateFeedError::DigestMismatch);
        }
        stage_response(
            response,
            destination,
            target.artifact_size,
            &target.artifact_sha256,
        )
        .await
    }
}

pub(crate) fn is_https_url(value: &str) -> bool {
    parse_https_url(value).is_ok()
}

fn parse_https_url(value: &str) -> Result<Url, UpdateFeedError> {
    let url = Url::parse(value).map_err(|_| UpdateFeedError::InvalidUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(UpdateFeedError::InvalidUrl);
    }
    Ok(url)
}

async fn bounded_body(mut response: Response, maximum: usize) -> Result<Vec<u8>, UpdateFeedError> {
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

async fn stage_response(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_urls_are_tls_only_and_non_credentialed() {
        assert!(is_https_url("https://updates.example.test/feed.json"));
        assert!(!is_https_url("http://updates.example.test/feed.json"));
        assert!(!is_https_url(
            "https://user:password@updates.example.test/feed.json"
        ));
        assert!(!is_https_url(
            "https://updates.example.test/feed.json#fragment"
        ));
    }
}
