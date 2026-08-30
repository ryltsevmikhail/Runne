//! Bounded HTTPS metadata and artifact transport for the native updater.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::redundant_pub_crate)]

use std::path::Path;
use std::time::Duration;

use reqwest::{Client, redirect::Policy};
use thiserror::Error;

use crate::{
    StagedUpdate, UpdateMetadataV2, UpdateTargetV2Binding, UpdateTrustError, UpdateTrustJournal,
    UpdateTrustRootV2, UpdateV2VerificationError, VerifiedUpdateV2, verify_update_v2,
};

#[path = "updater_feed/staging.rs"]
mod staging;
#[path = "updater_feed/url_policy.rs"]
mod url_policy;
use staging::{bounded_body, stage_response};
use url_policy::{TransportPolicy, parse_url};

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
    policy: TransportPolicy,
}

impl UpdateFeedClient {
    /// Builds a TLS-only client with no redirects and bounded request time.
    pub fn new() -> Result<Self, UpdateFeedError> {
        Self::build(TransportPolicy::Https, true)
    }

    #[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
    pub fn new_dev_loopback() -> Result<Self, UpdateFeedError> {
        Self::build(TransportPolicy::DevLoopback, false)
    }

    fn build(policy: TransportPolicy, https_only: bool) -> Result<Self, UpdateFeedError> {
        Client::builder()
            .https_only(https_only)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_mins(1))
            .build()
            .map(|client| Self { client, policy })
            .map_err(|_| UpdateFeedError::Transport)
    }

    /// Fetches strict signed metadata; cryptographic verification is separate.
    pub async fn fetch_metadata(
        &self,
        endpoint: &str,
    ) -> Result<UpdateMetadataV2, UpdateFeedError> {
        let url = parse_url(endpoint, self.policy)?;
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
        self.verify_metadata(
            &metadata,
            trust,
            binding,
            now_unix_seconds,
            current_version,
            rollback_floor,
        )
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
        let verified = self.verify_metadata(
            &metadata,
            trust,
            binding,
            now_unix_seconds,
            current_version,
            rollback_floor,
        )?;
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
        let url = parse_url(&target.artifact_url, self.policy)?;
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

    #[allow(clippy::too_many_arguments)]
    fn verify_metadata(
        &self,
        metadata: &UpdateMetadataV2,
        trust: &UpdateTrustRootV2,
        binding: &UpdateTargetV2Binding<'_>,
        now_unix_seconds: u64,
        current_version: &str,
        rollback_floor: &str,
    ) -> Result<VerifiedUpdateV2, UpdateFeedError> {
        let result = match self.policy {
            TransportPolicy::Https => verify_update_v2(
                metadata,
                trust,
                binding,
                now_unix_seconds,
                current_version,
                rollback_floor,
            ),
            #[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
            TransportPolicy::DevLoopback => crate::verify_update_v2_dev_loopback(
                metadata,
                trust,
                binding,
                now_unix_seconds,
                current_version,
                rollback_floor,
            ),
        };
        result.map_err(UpdateFeedError::Verification)
    }
}

pub(crate) fn is_update_url(value: &str, dev_loopback: bool) -> bool {
    #[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
    if dev_loopback {
        return parse_url(value, TransportPolicy::DevLoopback).is_ok();
    }
    let _ = dev_loopback;
    parse_url(value, TransportPolicy::Https).is_ok()
}
