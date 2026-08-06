use core::fmt;

use sha2::{Digest, Sha256};

use super::super::ProcessContractErrorV1;
use super::ProcessOutputStopEvidenceV1;

/// Opaque approved recipient for one transient output route.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ProcessOutputCallerIdV1([u8; 16]);

impl ProcessOutputCallerIdV1 {
    /// Creates a non-sentinel caller binding.
    pub(crate) fn new(value: [u8; 16]) -> Result<Self, ProcessContractErrorV1> {
        if value == [0; 16] {
            Err(ProcessContractErrorV1::EvidenceMalformed)
        } else {
            Ok(Self(value))
        }
    }

    /// CONTRACT_ONLY: runtime composition is intentionally deferred and this
    /// internal entry point has no public re-export.
    #[allow(dead_code)]
    pub(crate) fn from_validated_label(value: [u8; 16]) -> Result<Self, ProcessContractErrorV1> {
        Self::new(value)
    }
}

impl fmt::Debug for ProcessOutputCallerIdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessOutputCallerIdV1(redacted)")
    }
}

/// Digest and byte count for one captured prefix only.
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessOutputChannelEvidenceV1 {
    digest: [u8; 32],
    byte_count: u64,
    truncated: bool,
}

impl ProcessOutputChannelEvidenceV1 {
    /// Returns the SHA-256 digest of the captured prefix only.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the captured prefix's byte count only.
    #[must_use]
    pub const fn byte_count(&self) -> u64 {
        self.byte_count
    }

    /// Returns the source stop evidence's truncation state.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

impl fmt::Debug for ProcessOutputChannelEvidenceV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProcessOutputChannelEvidenceV1(bytes={},truncated={})",
            self.byte_count, self.truncated
        )
    }
}

/// Persistable output evidence with metadata only.
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessOutputEvidenceV1 {
    pub(super) stdout: ProcessOutputChannelEvidenceV1,
    pub(super) stderr: ProcessOutputChannelEvidenceV1,
}

impl ProcessOutputEvidenceV1 {
    /// Creates metadata for an empty capture without retaining raw bytes.
    pub(crate) fn empty() -> Self {
        Self {
            stdout: channel_evidence(&[], false),
            stderr: channel_evidence(&[], false),
        }
    }

    #[cfg(test)]
    pub(crate) const fn test_metadata(
        stdout_digest: [u8; 32],
        stdout_bytes: u64,
        stderr_digest: [u8; 32],
        stderr_bytes: u64,
    ) -> Self {
        Self {
            stdout: ProcessOutputChannelEvidenceV1 {
                digest: stdout_digest,
                byte_count: stdout_bytes,
                truncated: false,
            },
            stderr: ProcessOutputChannelEvidenceV1 {
                digest: stderr_digest,
                byte_count: stderr_bytes,
                truncated: false,
            },
        }
    }

    /// Returns metadata-only stdout evidence.
    #[must_use]
    pub const fn stdout(&self) -> &ProcessOutputChannelEvidenceV1 {
        &self.stdout
    }

    /// Returns metadata-only stderr evidence.
    #[must_use]
    pub const fn stderr(&self) -> &ProcessOutputChannelEvidenceV1 {
        &self.stderr
    }
}

impl fmt::Debug for ProcessOutputEvidenceV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessOutputEvidenceV1(redacted)")
    }
}

/// In-memory raw payload available only to the exact approved caller.
pub(crate) struct TransientProcessOutputChannelV1 {
    pub(super) caller: ProcessOutputCallerIdV1,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

impl TransientProcessOutputChannelV1 {
    /// Copies bounded raw bytes only for the exact approved caller.
    #[must_use]
    pub(crate) fn copy_for(
        &self,
        caller: &ProcessOutputCallerIdV1,
    ) -> Option<ProcessTransientOutputPayloadV1> {
        (self.caller == *caller).then(|| ProcessTransientOutputPayloadV1 {
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
        })
    }
}

impl fmt::Debug for TransientProcessOutputChannelV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransientProcessOutputChannelV1(redacted)")
    }
}

/// Exact approved recipient's bounded transient raw stream payload.
pub(crate) struct ProcessTransientOutputPayloadV1 {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl ProcessTransientOutputPayloadV1 {
    /// Returns the bounded transient stdout prefix.
    #[must_use]
    pub(crate) fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns the bounded transient stderr prefix.
    #[must_use]
    pub(crate) fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

impl fmt::Debug for ProcessTransientOutputPayloadV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessTransientOutputPayloadV1(redacted)")
    }
}

pub(super) fn channel_evidence(bytes: &[u8], truncated: bool) -> ProcessOutputChannelEvidenceV1 {
    ProcessOutputChannelEvidenceV1 {
        digest: Sha256::digest(bytes).into(),
        byte_count: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        truncated,
    }
}

/// Result of bounded capture; only its transient channel owns raw bytes.
pub(crate) struct ProcessCapturedOutputV1 {
    pub(super) evidence: ProcessOutputEvidenceV1,
    pub(super) transient: TransientProcessOutputChannelV1,
    pub(super) stop_evidence: Option<ProcessOutputStopEvidenceV1>,
}

impl ProcessCapturedOutputV1 {
    /// Returns metadata-only output evidence.
    #[must_use]
    pub(crate) const fn evidence(&self) -> &ProcessOutputEvidenceV1 {
        &self.evidence
    }

    /// Returns the non-persisted exact-caller transient channel.
    #[must_use]
    pub(crate) const fn transient(&self) -> &TransientProcessOutputChannelV1 {
        &self.transient
    }

    /// Returns stop metadata when bounded capture stopped early.
    #[must_use]
    pub(crate) const fn stop_evidence(&self) -> Option<ProcessOutputStopEvidenceV1> {
        self.stop_evidence
    }

    pub(crate) fn into_evidence_and_transient(
        self,
    ) -> (ProcessOutputEvidenceV1, TransientProcessOutputChannelV1) {
        (self.evidence, self.transient)
    }
}

impl fmt::Debug for ProcessCapturedOutputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessCapturedOutputV1(redacted)")
    }
}
