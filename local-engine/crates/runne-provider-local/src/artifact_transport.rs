//! Ancillary-fd ↔ frame binding: exactly one fd for exactly one
//! authenticated `load_model` frame; metadata must match the grant;
//! every error path closes all received descriptors. Fully safe: reads
//! go through rustix over the owned descriptor (workspace forbids
//! `unsafe`), contents remain untrusted data for the parse layer.

use crate::error::ProviderError;
use crate::grant::{ArtifactGrant, GrantRole};
use runne_engine_broker::broker::artifact::FileIdentity;
use std::os::unix::net::UnixStream;

/// What a frame must carry to claim an fd.
pub struct FrameClaim<'a> {
    pub frame_type: &'a str, // "load_model" (host) | "backend_load" (worker)
    pub artifact_digest: &'a str,
    pub byte_len: u64,
}

/// Binds exactly one received fd to one frame. Duplicate fds (same raw
/// number arriving twice) are rejected; mismatched metadata closes all
/// fds; on success the fd is exposed as a read-only byte source whose
/// length and pinned identity were re-verified against the grant.
#[derive(Debug)]
pub struct BoundFd {
    fd: rustix::fd::OwnedFd,
    byte_len: u64,
}

impl BoundFd {
    /// Seeks to `offset` and fills `buf` fully from the granted artifact.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), ProviderError> {
        use rustix::fs::SeekFrom;
        rustix::fs::seek(&self.fd, SeekFrom::Start(offset)).map_err(|e| {
            ProviderError::Broker(runne_engine_broker::BrokerError::OpenFailed(e.to_string()))
        })?;
        let mut done = 0usize;
        while done < buf.len() {
            let n = rustix::io::read(&self.fd, &mut buf[done..]).map_err(|e| {
                ProviderError::Broker(runne_engine_broker::BrokerError::OpenFailed(e.to_string()))
            })?;
            if n == 0 {
                return Err(ProviderError::LengthMismatch);
            }
            done += n;
        }
        Ok(())
    }

    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

/// Receives exactly one ancillary fd from the broker stream, binds it to
/// the frame claim, and re-verifies the pinned identity against the grant
/// (defense in depth against a hostile sender swapping the descriptor).
pub fn bind_frame_fd(
    received: Vec<rustix::fd::OwnedFd>,
    socket: &UnixStream,
    claim: &FrameClaim<'_>,
    grant: &ArtifactGrant,
    pinned: &FileIdentity,
) -> Result<BoundFd, ProviderError> {
    // Exactly one fd for one frame; every other count closes all fds.
    let mut fds = received;
    if fds.len() != 1 {
        fds.clear(); // drops (closes) every received descriptor
        return Err(if fds.is_empty() {
            ProviderError::FdMissing
        } else {
            ProviderError::FdDuplicate
        });
    }
    // Role ↔ frame type binding.
    let expected_type = match grant.role {
        GrantRole::HostInspection => "load_model",
        GrantRole::BackendWorkerLoad { .. } => "backend_load",
    };
    if claim.frame_type != expected_type {
        fds.clear();
        return Err(ProviderError::FrameMismatch);
    }
    // Frame metadata must match the grant binding exactly.
    if claim.artifact_digest != grant.artifact_digest || claim.byte_len != grant.byte_len {
        fds.clear();
        return Err(ProviderError::FrameMismatch);
    }
    // CLOEXEC + verify on the received descriptor (Darwin drops the
    // sender's flag across SCM_RIGHTS).
    let fd = runne_engine_broker::broker::artifact_unix::recv_one(socket)?;
    // Pinned identity re-verified on the received fd.
    let st = rustix::fs::fstat(&fd).map_err(|e| {
        ProviderError::Broker(runne_engine_broker::BrokerError::OpenFailed(e.to_string()))
    })?;
    if st.st_dev as u64 != pinned.dev || st.st_ino as u64 != pinned.ino {
        fds.clear();
        return Err(ProviderError::FrameMismatch);
    }
    if st.st_size != grant.byte_len as i64 {
        return Err(ProviderError::LengthMismatch);
    }
    Ok(BoundFd {
        fd,
        byte_len: grant.byte_len,
    })
}

/// SCM_RIGHTS send half (broker side).
pub fn send_grant_fd(
    socket: &UnixStream,
    fd: rustix::fd::BorrowedFd<'_>,
) -> Result<(), ProviderError> {
    runne_engine_broker::broker::artifact_unix::send_one(socket, fd).map_err(ProviderError::from)
}
