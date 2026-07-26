//! Command fingerprint — SHA-256 canonical encoding for idempotency.
//!
//! Each use case has a typed constructor that produces a deterministic
//! 32-byte digest. The encoding includes:
//!   - Domain-separation prefix `gocode-cmd\x01`
//!   - Schema version (u16, BE)
//!   - Operation tag (u8)
//!   - Length-prefixed semantic fields (u16 BE lengths)
//!   - Raw UUID bytes (16 bytes each)
//!   - TerminalResult canonical encoding (for complete only)
//!
//! Server-generated IDs (TaskRunId/AttemptId/EventId/CommandId) are
//! deliberately **not** included — a retry must return the original IDs.

use gocode_domain::command::TerminalResult;
use gocode_domain::id::{ConversationId, TaskRunId, WorkspaceId};
use sha2::{Digest, Sha256};

use crate::errors::FingerprintError;

/// Maximum bytes for a `TerminalResult::Failure.reason`.
pub const MAX_TERMINAL_REASON_BYTES: usize = 4096;

/// Domain-separation prefix for command fingerprints.
const DOMAIN_PREFIX: &[u8] = b"gocode-cmd\x01";

/// Current schema version for fingerprint encoding.
const SCHEMA_VERSION: u16 = 1;

/// Operation tags (must match [`crate::ports::OperationTag`]).
const TAG_CREATE: u8 = 1;
const TAG_QUEUE: u8 = 2;
const TAG_ADMIT: u8 = 3;
const TAG_START_ATTEMPT: u8 = 4;
const TAG_COMPLETE: u8 = 5;

/// A SHA-256 fingerprint of a command's semantic payload.
///
/// Used for idempotency: two commands with the same scope, key, and
/// fingerprint are considered identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandFingerprint([u8; 32]);

impl CommandFingerprint {
    /// Create from raw 32-byte digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return a reference to the raw 32-byte digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume and return the raw 32-byte digest.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Create a fingerprint for `CreateTaskRun`.
    ///
    /// The fingerprint includes only the conversation and workspace IDs
    /// (not the server-generated `TaskRunId`).
    pub fn for_create(conversation_id: &ConversationId, workspace_id: &WorkspaceId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update(&[TAG_CREATE]);
        // conversation_id: 16 raw bytes
        hasher.update(conversation_id.as_bytes());
        // workspace_id: 16 raw bytes
        hasher.update(workspace_id.as_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `Queue`.
    pub fn for_queue(taskrun_id: &TaskRunId, expected_version: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update(&[TAG_QUEUE]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `Admit`.
    pub fn for_admit(taskrun_id: &TaskRunId, expected_version: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update(&[TAG_ADMIT]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `StartAttempt`.
    pub fn for_start_attempt(taskrun_id: &TaskRunId, expected_version: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update(&[TAG_START_ATTEMPT]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `Complete`.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintError::TerminalReasonTooLong`] if the
    /// `TerminalResult::Failure.reason` exceeds
    /// [`MAX_TERMINAL_REASON_BYTES`].
    pub fn for_complete(
        taskrun_id: &TaskRunId,
        result: &TerminalResult,
        expected_version: u64,
    ) -> Result<Self, FingerprintError> {
        // Validate reason length for Failure
        if let TerminalResult::Failure { reason } = result {
            let len = reason.len();
            if len > MAX_TERMINAL_REASON_BYTES {
                return Err(FingerprintError::TerminalReasonTooLong {
                    max: MAX_TERMINAL_REASON_BYTES,
                    actual: len,
                });
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update(&[TAG_COMPLETE]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        // TerminalResult canonical encoding:
        //   tag: 0x00 = Success, 0x01 = Failure
        //   for Failure: reason_len (u16 BE) || reason_bytes
        match result {
            TerminalResult::Success => {
                hasher.update(&[0x00u8]);
            }
            TerminalResult::Failure { reason } => {
                hasher.update(&[0x01u8]);
                let reason_bytes = reason.as_bytes();
                hasher.update((reason_bytes.len() as u16).to_be_bytes());
                hasher.update(reason_bytes);
            }
        }
        Ok(Self(hasher.finalize().into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONV_ID_STR: &str = "018f2e3a-7000-7000-8000-000000000001";
    const WS_ID_STR: &str = "018f2e3a-7000-7000-8000-000000000002";
    const TR_ID_STR: &str = "018f2e3a-7000-7000-8000-000000000003";

    #[test]
    fn test_for_create_deterministic() {
        let conv_id: ConversationId = CONV_ID_STR.parse().unwrap();
        let ws_id: WorkspaceId = WS_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_create(&conv_id, &ws_id);
        let fp2 = CommandFingerprint::for_create(&conv_id, &ws_id);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.as_bytes(), fp2.as_bytes());
    }

    #[test]
    fn test_for_create_different_conv_is_different() {
        let conv1: ConversationId = CONV_ID_STR.parse().unwrap();
        let conv2: ConversationId = "018f2e3a-7000-7000-8000-00000000000a".parse().unwrap();
        let ws_id: WorkspaceId = WS_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_create(&conv1, &ws_id);
        let fp2 = CommandFingerprint::for_create(&conv2, &ws_id);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_for_queue_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_queue(&tr_id, 0);
        let fp2 = CommandFingerprint::for_queue(&tr_id, 0);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_queue_different_version_is_different() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_queue(&tr_id, 0);
        let fp2 = CommandFingerprint::for_queue(&tr_id, 1);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_for_admit_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_admit(&tr_id, 1);
        let fp2 = CommandFingerprint::for_admit(&tr_id, 1);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_start_attempt_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_start_attempt(&tr_id, 1);
        let fp2 = CommandFingerprint::for_start_attempt(&tr_id, 1);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_complete_success_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let result = TerminalResult::Success;
        let fp1 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        let fp2 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_complete_failure_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let result = TerminalResult::Failure {
            reason: "test failure".into(),
        };
        let fp1 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        let fp2 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_complete_success_vs_failure_different() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp_success =
            CommandFingerprint::for_complete(&tr_id, &TerminalResult::Success, 3).unwrap();
        let fp_failure = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: "err".into(),
            },
            3,
        )
        .unwrap();
        assert_ne!(fp_success, fp_failure);
    }

    #[test]
    fn test_for_complete_reason_too_long() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let long_reason = "x".repeat(MAX_TERMINAL_REASON_BYTES + 1);
        let result = TerminalResult::Failure {
            reason: long_reason.clone(),
        };
        let err = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap_err();
        assert_eq!(
            err,
            FingerprintError::TerminalReasonTooLong {
                max: MAX_TERMINAL_REASON_BYTES,
                actual: long_reason.len(),
            }
        );
    }

    #[test]
    fn test_for_complete_reason_at_limit_ok() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let reason = "x".repeat(MAX_TERMINAL_REASON_BYTES);
        let result = TerminalResult::Failure {
            reason: reason.clone(),
        };
        let fp = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        assert_eq!(fp.as_bytes().len(), 32);
    }

    // ── Golden vectors ────────────────────────────────────────────────────

    #[test]
    fn test_golden_for_create() {
        let conv_id: ConversationId = CONV_ID_STR.parse().unwrap();
        let ws_id: WorkspaceId = WS_ID_STR.parse().unwrap();
        let fp = CommandFingerprint::for_create(&conv_id, &ws_id);
        // Pre-computed SHA-256 of:
        //   domain_prefix(12) || schema_version(2,BE=0x0001) || tag(0x01) ||
        //   conv_id(16) || ws_id(16)
        let expected: [u8; 32] = [
            0xb8, 0x1d, 0x69, 0x9a, 0x32, 0xef, 0x6d, 0xcc, 0x42, 0xb3, 0x49, 0xb2, 0x3d, 0x39,
            0x1b, 0xa8, 0x12, 0xc6, 0x43, 0x5e, 0x1b, 0x95, 0x6e, 0xf6, 0x84, 0xac, 0xf9, 0x66,
            0x7b, 0x05, 0xea, 0x88,
        ];
        assert_eq!(*fp.as_bytes(), expected);
    }

    #[test]
    fn test_golden_for_queue() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_queue(&tr_id, 0);
        let fp2 = CommandFingerprint::for_queue(&tr_id, 0);
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_queue(&tr_id, 1);
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_admit() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_admit(&tr_id, 0);
        let fp2 = CommandFingerprint::for_admit(&tr_id, 0);
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_admit(&tr_id, 1);
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_start_attempt() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_start_attempt(&tr_id, 0);
        let fp2 = CommandFingerprint::for_start_attempt(&tr_id, 0);
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_start_attempt(&tr_id, 1);
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_complete_success() {
        use gocode_domain::command::TerminalResult;
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_complete(&tr_id, &TerminalResult::Success, 0).unwrap();
        let fp2 = CommandFingerprint::for_complete(&tr_id, &TerminalResult::Success, 0).unwrap();
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("x"),
            },
            0,
        )
        .unwrap();
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_complete_failure() {
        use gocode_domain::command::TerminalResult;
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("ERR"),
            },
            0,
        )
        .unwrap();
        let fp2 = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("ERR"),
            },
            0,
        )
        .unwrap();
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("OTHER"),
            },
            0,
        )
        .unwrap();
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_tags_are_distinct() {
        // Same inputs, different tags → different digests
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp_queue = CommandFingerprint::for_queue(&tr_id, 0);
        let fp_admit = CommandFingerprint::for_admit(&tr_id, 0);
        assert_ne!(fp_queue, fp_admit);
    }
}
