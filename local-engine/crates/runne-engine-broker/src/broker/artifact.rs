//! Artifact broker primitives: no-follow open of catalog-owned content
//! addresses, identity pinning, one-time descriptors, grant state machine
//! (INTERFACES §ModelArtifactBrokerPort, SECURITY §artifact boundary).
//! Pure in-memory + fd operations: no process execution, no network.

use crate::broker::error::BrokerError;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{Mode, OFlags, fstat, openat};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Where the artifact broker opens catalog content: a directory holding
/// content-addressed blobs (names = lowercase sha256 hex).
#[derive(Debug, Clone)]
pub struct BlobDir(pub std::path::PathBuf);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRole {
    HostInspection,
    BackendWorkerLoad { worker_generation: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantBinding {
    pub role: GrantRole,
    pub host_generation: u64,
    pub load_id: [u8; 16],
    pub session_id: [u8; 16],
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantState {
    Issued,
    Transferred,
    Consumed,
    RecipientClosed,
    RevokedPreTransfer,
    TerminationRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeDisposition {
    Revoked,
    TerminationRequired,
    AlreadyRevoked,
}

struct GrantRecord {
    state: GrantState,
    role: GrantRole,
    host_generation: u64,
    load_id: [u8; 16],
    session_id: [u8; 16],
    expires_at: u64,
    identity: FileIdentity,
    byte_len: u64,
    /// Broker-owned descriptor while the grant is `Issued`.
    descriptor: Option<OwnedFd>,
}

/// Security broker owning descriptors and the grant ledger.
#[derive(Default)]
pub struct SecurityBroker {
    grants: BTreeMap<u64, GrantRecord>,
    next_id: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl SecurityBroker {
    /// Opens the blob no-follow/read-only, pins identity, issues a
    /// one-time grant bound to the exact binding.
    pub fn issue(
        &mut self,
        blobs: &BlobDir,
        digest_hex: &str,
        declared_len: u64,
        binding: GrantBinding,
    ) -> Result<u64, BrokerError> {
        if digest_hex.len() != 64 || !digest_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(BrokerError::BadDigestFormat);
        }
        let dir = rustix::fs::open(
            &blobs.0,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| BrokerError::OpenFailed(e.to_string()))?;
        let fd = openat(
            &dir,
            digest_hex,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| match e {
            rustix::io::Errno::LOOP => BrokerError::SymlinkRejected,
            rustix::io::Errno::NOENT => BrokerError::OpenFailed("no such blob".into()),
            other => BrokerError::OpenFailed(other.to_string()),
        })?;
        let st_fd = fstat(&fd).map_err(|e| BrokerError::OpenFailed(e.to_string()))?;
        const S_IFMT: u16 = 0o170_000;
        const S_IFREG: u16 = 0o100_000;
        if st_fd.st_mode & S_IFMT != S_IFREG {
            return Err(BrokerError::NotRegularFile);
        }
        if st_fd.st_size != declared_len as i64 {
            return Err(BrokerError::LengthMismatch);
        }
        // Path-side stat after open (swap detection): dev/ino must agree.
        let path = blobs.0.join(digest_hex);
        let st_path = rustix::fs::stat(&path).map_err(|_| BrokerError::IdentityUnstable)?;
        let identity = FileIdentity {
            dev: st_fd.st_dev as u64,
            ino: st_fd.st_ino as u64,
        };
        if st_path.st_dev as u64 != identity.dev || st_path.st_ino as u64 != identity.ino {
            return Err(BrokerError::IdentityUnstable);
        }
        // Duplicate with close-on-exec for the grant lifetime descriptor.
        let descriptor = rustix::io::fcntl_dupfd_cloexec(&fd, 0)
            .map_err(|e| BrokerError::OpenFailed(e.to_string()))?;
        drop(fd);
        self.next_id += 1;
        let id = self.next_id;
        self.grants.insert(
            id,
            GrantRecord {
                state: GrantState::Issued,
                role: binding.role,
                host_generation: binding.host_generation,
                load_id: binding.load_id,
                session_id: binding.session_id,
                expires_at: binding.expires_at,
                identity,
                byte_len: declared_len,
                descriptor: Some(descriptor),
            },
        );
        Ok(id)
    }

    /// Moves the broker-owned descriptor out at transfer time (single
    /// ownership; broker no longer holds a copy).
    pub fn transfer_owned(
        &mut self,
        grant_id: u64,
        claim: &GrantBinding,
    ) -> Result<OwnedFd, BrokerError> {
        let now_ts = now();
        let record = self
            .grants
            .get_mut(&grant_id)
            .ok_or(BrokerError::GrantMissing)?;
        if record.expires_at <= now_ts {
            return Err(BrokerError::GrantExpired);
        }
        if record.state != GrantState::Issued {
            // Precise typed errors: revoked is distinguishable from other
            // terminal states, but every non-Issued state blocks the claim.
            return Err(match record.state {
                GrantState::RevokedPreTransfer => BrokerError::AlreadyRevoked,
                _ => BrokerError::AlreadyConsumed,
            });
        }
        if record.role != claim.role {
            return Err(BrokerError::WrongRole);
        }
        if record.host_generation != claim.host_generation {
            return Err(BrokerError::WrongGeneration);
        }
        if record.load_id != claim.load_id {
            return Err(BrokerError::WrongLoadId);
        }
        if record.session_id != claim.session_id {
            return Err(BrokerError::WrongSession);
        }
        record.state = GrantState::Transferred;
        record.descriptor.take().ok_or(BrokerError::AlreadyConsumed)
    }

    /// Revoke: pre-transfer closes the broker descriptor and blocks
    /// consumption; post-transfer the broker cannot reach the recipient
    /// duplicate — records TerminationRequired for the bound generation.
    pub fn revoke(&mut self, grant_id: u64) -> Result<RevokeDisposition, BrokerError> {
        let record = self
            .grants
            .get_mut(&grant_id)
            .ok_or(BrokerError::GrantMissing)?;
        match record.state {
            GrantState::Issued => {
                record.descriptor = None; // closes the owned fd
                record.state = GrantState::RevokedPreTransfer;
                Ok(RevokeDisposition::Revoked)
            }
            GrantState::Transferred | GrantState::Consumed | GrantState::RecipientClosed => {
                record.state = GrantState::TerminationRequired;
                Ok(RevokeDisposition::TerminationRequired)
            }
            GrantState::RevokedPreTransfer | GrantState::TerminationRequired => {
                Ok(RevokeDisposition::AlreadyRevoked)
            }
        }
    }

    /// Recipient acknowledges close. Worker-role grants require
    /// worker-terminal evidence (`worker:<generation>`); host evidence is
    /// insufficient for a worker grant.
    /// `Transferred → Consumed`: recipient acknowledged taking the
    /// descriptor (evidence required; worker grants need worker proof).
    pub fn mark_consumed(
        &mut self,
        grant_id: u64,
        evidence: &str,
    ) -> Result<GrantState, BrokerError> {
        let record = self
            .grants
            .get_mut(&grant_id)
            .ok_or(BrokerError::GrantMissing)?;
        if record.state != GrantState::Transferred {
            return Err(BrokerError::AlreadyConsumed);
        }
        match record.role {
            GrantRole::BackendWorkerLoad { worker_generation } => {
                if evidence != format!("worker:{worker_generation}") {
                    return Err(BrokerError::EvidenceInsufficient);
                }
            }
            GrantRole::HostInspection => {
                if evidence.is_empty() {
                    return Err(BrokerError::EvidenceInsufficient);
                }
            }
        }
        record.state = GrantState::Consumed;
        Ok(record.state)
    }

    /// Recipient close: legal only from Consumed (post-use ack).
    pub fn recipient_closed(
        &mut self,
        grant_id: u64,
        _evidence: &str,
    ) -> Result<GrantState, BrokerError> {
        let record = self
            .grants
            .get_mut(&grant_id)
            .ok_or(BrokerError::GrantMissing)?;
        if record.state != GrantState::Consumed {
            return Err(BrokerError::AlreadyConsumed);
        }
        record.state = GrantState::RecipientClosed;
        Ok(record.state)
    }

    pub fn state(&self, grant_id: u64) -> Result<GrantState, BrokerError> {
        Ok(self
            .grants
            .get(&grant_id)
            .ok_or(BrokerError::GrantMissing)?
            .state)
    }

    /// The live descriptor of an `Issued` grant (for SCM_RIGHTS send by
    /// the broker transport).
    pub fn issued_descriptor(&self, grant_id: u64) -> Result<BorrowedFd<'_>, BrokerError> {
        let record = self
            .grants
            .get(&grant_id)
            .ok_or(BrokerError::GrantMissing)?;
        if record.state != GrantState::Issued {
            return Err(BrokerError::AlreadyConsumed);
        }
        record
            .descriptor
            .as_ref()
            .map(|fd| fd.as_fd())
            .ok_or(BrokerError::AlreadyConsumed)
    }

    /// Identity pinned at issue time (for transport metadata match).
    pub fn identity(&self, grant_id: u64) -> Result<(FileIdentity, u64), BrokerError> {
        let record = self
            .grants
            .get(&grant_id)
            .ok_or(BrokerError::GrantMissing)?;
        Ok((record.identity, record.byte_len))
    }
}
