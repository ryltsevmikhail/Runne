//! `ModelArtifactBrokerPort`: issues/revokes one-time load grants bound
//! to exact catalog identities (INTERFACES §ModelArtifactBrokerPort).
//! Delegates descriptor mechanics to `runne-engine-broker`; binds grants to
//! the installation's content address from the catalog.

use crate::error::ProviderError;
use crate::grant::{ArtifactGrant, ArtifactGrantRequest, GrantRole};
use runne_engine_broker::broker::artifact::{
    BlobDir, GrantBinding, GrantRole as SecRole, SecurityBroker,
};
use runne_model_store::ModelArtifactStore;

pub struct ModelArtifactBrokerPort {
    catalog: ModelArtifactStore,
    security: SecurityBroker,
}

impl ModelArtifactBrokerPort {
    pub fn new(catalog: ModelArtifactStore) -> Result<Self, ProviderError> {
        Ok(Self {
            catalog,
            security: SecurityBroker::default(),
        })
    }

    /// Issues a one-time grant: the installation must exist, the declared
    /// digest/length must match the catalog record exactly, and the
    /// binding pins role/generation/load/session.
    pub fn issue_grant(
        &mut self,
        request: &ArtifactGrantRequest,
    ) -> Result<ArtifactGrant, ProviderError> {
        let installed = self.catalog.get_exact_by_digest(&request.manifest_digest)?;
        eprintln!(
            "BROKER DBG lookup digest={} found={:?}",
            request.manifest_digest,
            installed.is_some()
        );
        let installed = installed.ok_or(ProviderError::ArtifactNotInstalled)?;
        if installed.artifact_digest != request.artifact_digest {
            return Err(ProviderError::FrameMismatch);
        }
        if installed.byte_len != request.byte_len {
            return Err(ProviderError::FrameMismatch);
        }
        let binding = GrantBinding {
            role: request.role.to_security(),
            host_generation: request.host_generation,
            load_id: request.load_id,
            session_id: request.session_id,
            expires_at: runne_model_store::catalog_now() + request.ttl_secs,
        };
        let digest_hex = request
            .artifact_digest
            .strip_prefix("sha256:")
            .ok_or(ProviderError::FrameMismatch)?
            .to_string();
        let blobs = BlobDir(self.catalog.root().join("blobs"));
        let grant_id = self
            .security
            .issue(&blobs, &digest_hex, request.byte_len, binding)
            .map_err(ProviderError::Broker)?;
        Ok(ArtifactGrant {
            grant_id,
            artifact_digest: request.artifact_digest.clone(),
            byte_len: request.byte_len,
            role: request.role,
            host_generation: request.host_generation,
            load_id: request.load_id,
            expires_at: binding.expires_at,
        })
    }

    /// Moves the broker-owned descriptor out for SCM_RIGHTS transfer to
    /// the authenticated recipient (one-time).
    pub fn consume_grant(
        &mut self,
        grant_id: u64,
        request: &ArtifactGrantRequest,
    ) -> Result<rustix::fd::OwnedFd, ProviderError> {
        let binding = GrantBinding {
            role: request.role.to_security(),
            host_generation: request.host_generation,
            load_id: request.load_id,
            session_id: request.session_id,
            expires_at: 0,
        };
        Ok(self.security.transfer_owned(grant_id, &binding)?)
    }

    /// `Transferred → Consumed` with role-appropriate evidence.
    pub fn mark_consumed(
        &mut self,
        grant_id: u64,
        evidence: &str,
    ) -> Result<runne_engine_broker::broker::artifact::GrantState, ProviderError> {
        Ok(self.security.mark_consumed(grant_id, evidence)?)
    }

    /// Revoke with pre/post-transfer dispositions (see SecurityBroker).
    pub fn revoke_grant(
        &mut self,
        grant_id: u64,
    ) -> Result<runne_engine_broker::broker::artifact::RevokeDisposition, ProviderError> {
        Ok(self.security.revoke(grant_id)?)
    }

    /// Recipient acknowledges close with role-appropriate evidence.
    pub fn recipient_closed(
        &mut self,
        grant_id: u64,
        evidence: &str,
    ) -> Result<runne_engine_broker::broker::artifact::GrantState, ProviderError> {
        Ok(self.security.recipient_closed(grant_id, evidence)?)
    }

    /// Live issued descriptor for SCM_RIGHTS send.
    pub fn issued_descriptor(
        &self,
        grant_id: u64,
    ) -> Result<rustix::fd::BorrowedFd<'_>, ProviderError> {
        Ok(self.security.issued_descriptor(grant_id)?)
    }

    /// Identity pinned at issue (for frame metadata validation).
    pub fn grant_identity(
        &self,
        grant_id: u64,
    ) -> Result<(runne_engine_broker::broker::artifact::FileIdentity, u64), ProviderError> {
        Ok(self.security.identity(grant_id)?)
    }

    #[allow(dead_code)]
    fn _role_witness(r: GrantRole) -> SecRole {
        r.to_security()
    }
}
