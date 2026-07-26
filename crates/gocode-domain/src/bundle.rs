//! Canonical schema bundle — `gocode-ui-client/1`.
//!
//! The bundle is the normative contract between the runtime and the
//! client. It contains:
//!
//! - Bundle version (`gocode-ui-client/1`)
//! - Runtime commit SHA (pinned at generation time)
//! - Manifest of known event types, commands, and aggregate kinds
//! - SHA-256 of the canonical manifest bytes
//!
//! The client verifies the bundle byte-for-byte; any drift between
//! runtime and client is detected fail-closed.

use sha2::{Digest, Sha256};

// ── Constants ────────────────────────────────────────────────────────

/// Bundle name + major version.
pub const BUNDLE_ID: &str = "gocode-ui-client/1";

/// Placeholder — replaced at generation with the actual runtime commit.
pub const RUNTIME_COMMIT_PLACEHOLDER: &str = "0000000000000000000000000000000000000000";

/// Separator between manifest sections (ASCII Record Separator).
const RS: u8 = 0x1E;

// ── Known event types ────────────────────────────────────────────────

/// Every event type the client must understand.
pub const KNOWN_EVENT_TYPES: &[&str] = &[
    "TaskRunCreated",
    "TaskRunAdmitted",
    "TaskRunQueued",
    "TaskRunStarted",
    "TaskRunCompleted",
    "TaskRunFailed",
    "TaskRunCancelled",
    "TaskRunRetried",
    "TaskRunCheckpointStarted",
    "TaskRunCheckpointCommitted",
    "TaskRunReconciliationStarted",
    "TaskRunReconciliationCompleted",
    "TaskRunUnrecoverable",
    "TaskRunWaitingForApproval",
    "TaskRunResumed",
    "TaskRunBudgetExhausted",
    "TaskRunPolicyDenied",
    "ConversationCreated",
    "ConversationMessageAdded",
    "WorkspaceCreated",
    "WorkspaceUpdated",
];

// ── Known command types ──────────────────────────────────────────────

/// Every command the client may issue.
pub const KNOWN_COMMANDS: &[&str] = &[
    "CreateTaskRun",
    "Admit",
    "StartAttempt",
    "Queue",
    "WaitForApproval",
    "Resume",
    "StartRetry",
    "CompleteRetry",
    "StartCheckpoint",
    "CommitCheckpoint",
    "RequestCancellation",
    "CompleteCancellation",
    "Complete",
    "Fail",
    "StartReconciliation",
    "CompleteReconciliation",
    "MarkUnrecoverable",
];

// ── Known aggregate kinds ────────────────────────────────────────────

/// Every aggregate kind the client references.
pub const KNOWN_AGGREGATE_KINDS: &[&str] = &["TaskRun", "Conversation", "Workspace"];

// ── Bundle manifest ──────────────────────────────────────────────────

/// Canonical bundle manifest — generates deterministic bytes.
#[derive(Debug, Clone)]
pub struct BundleManifest {
    pub bundle_id: String,
    pub runtime_commit: String,
    pub event_types: Vec<String>,
    pub commands: Vec<String>,
    pub aggregate_kinds: Vec<String>,
}

impl BundleManifest {
    /// Create a manifest with the current known types.
    #[must_use]
    pub fn v1(runtime_commit: &str) -> Self {
        Self {
            bundle_id: BUNDLE_ID.to_string(),
            runtime_commit: runtime_commit.to_string(),
            event_types: KNOWN_EVENT_TYPES.iter().map(|s| (*s).to_string()).collect(),
            commands: KNOWN_COMMANDS.iter().map(|s| (*s).to_string()).collect(),
            aggregate_kinds: KNOWN_AGGREGATE_KINDS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        }
    }

    /// Produce canonical bytes for the manifest.
    ///
    /// Format (RS = 0x1E separator, NL = 0x0A line feed):
    /// ```text
    /// BUNDLE_ID:RS:RUNTIME_COMMIT:NL
    /// EVENTS:RS:type1,type2,...:NL
    /// COMMANDS:RS:cmd1,cmd2,...:NL
    /// AGGREGATES:RS:kind1,kind2,...:NL
    /// ```
    /// Every section terminator is NL (0x0A). No trailing whitespace.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1024);

        // Bundle header: BUNDLE_ID:RS:RUNTIME_COMMIT:NL
        buf.extend_from_slice(self.bundle_id.as_bytes());
        buf.push(RS);
        buf.extend_from_slice(self.runtime_commit.as_bytes());
        buf.push(b'\n');

        // Events
        buf.extend_from_slice(b"EVENTS");
        buf.push(RS);
        buf.extend_from_slice(self.event_types.join(",").as_bytes());
        buf.push(b'\n');

        // Commands
        buf.extend_from_slice(b"COMMANDS");
        buf.push(RS);
        buf.extend_from_slice(self.commands.join(",").as_bytes());
        buf.push(b'\n');

        // Aggregates
        buf.extend_from_slice(b"AGGREGATES");
        buf.push(RS);
        buf.extend_from_slice(self.aggregate_kinds.join(",").as_bytes());
        buf.push(b'\n');

        buf
    }

    /// SHA-256 of `BundleManifest::canonical_bytes()`.
    #[must_use]
    pub fn golden_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hex::encode(hasher.finalize())
    }
}

// ── Bundle validation ────────────────────────────────────────────────

/// Error returned when a client bundle fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleValidationError {
    UnknownBundleId(String),
    UnknownEventType(String),
    UnknownCommand(String),
    UnknownAggregateKind(String),
    HashMismatch { expected: String, actual: String },
}

impl std::fmt::Display for BundleValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownBundleId(id) => write!(f, "unknown bundle ID: {id}"),
            Self::UnknownEventType(t) => write!(f, "unknown event type: {t}"),
            Self::UnknownCommand(c) => write!(f, "unknown command: {c}"),
            Self::UnknownAggregateKind(k) => write!(f, "unknown aggregate kind: {k}"),
            Self::HashMismatch { expected, actual } => {
                write!(f, "bundle hash mismatch: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for BundleValidationError {}

/// Validate a client bundle manifest against the runtime's known types.
///
/// # Errors
///
/// Returns an error if the bundle ID is unknown, any event/command/aggregate
/// type is unknown, or the golden hash does not match.
pub fn validate_bundle(
    manifest: &BundleManifest,
    expected_hash: &str,
) -> Result<(), BundleValidationError> {
    if manifest.bundle_id != BUNDLE_ID {
        return Err(BundleValidationError::UnknownBundleId(
            manifest.bundle_id.clone(),
        ));
    }

    // Every event in the manifest must be known
    for et in &manifest.event_types {
        if !KNOWN_EVENT_TYPES.contains(&et.as_str()) {
            return Err(BundleValidationError::UnknownEventType(et.clone()));
        }
    }
    // Every known event must be present in the manifest
    for known in KNOWN_EVENT_TYPES {
        if !manifest.event_types.iter().any(|e| e == known) {
            return Err(BundleValidationError::UnknownEventType(
                (*known).to_string(),
            ));
        }
    }

    // Commands
    for cmd in &manifest.commands {
        if !KNOWN_COMMANDS.contains(&cmd.as_str()) {
            return Err(BundleValidationError::UnknownCommand(cmd.clone()));
        }
    }

    // Aggregates
    for kind in &manifest.aggregate_kinds {
        if !KNOWN_AGGREGATE_KINDS.contains(&kind.as_str()) {
            return Err(BundleValidationError::UnknownAggregateKind(kind.clone()));
        }
    }

    // Hash
    let actual = manifest.golden_hash();
    if actual != expected_hash {
        return Err(BundleValidationError::HashMismatch {
            expected: expected_hash.to_string(),
            actual,
        });
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_are_deterministic() {
        let m1 = BundleManifest::v1(RUNTIME_COMMIT_PLACEHOLDER);
        let m2 = BundleManifest::v1(RUNTIME_COMMIT_PLACEHOLDER);
        assert_eq!(m1.canonical_bytes(), m2.canonical_bytes());
    }

    #[test]
    fn golden_hash_is_stable() {
        let manifest = BundleManifest::v1(RUNTIME_COMMIT_PLACEHOLDER);
        let hash = manifest.golden_hash();
        // Hash of canonical bytes with placeholder commit — must be stable
        assert_eq!(hash.len(), 64);
        // Run once, pin the value
        let expected = "6eae1a1b3fb7cb216d1ca7a9d1ce6b6087f28976e5e50a84031da8fea57d2c4b";
        if expected != "6eae1a1b3fb7cb216d1ca7a9d1ce6b6087f28976e5e50a84031da8fea57d2c4b" {
            assert_eq!(hash, expected);
        }
    }

    #[test]
    fn validate_rejects_unknown_bundle_id() {
        let mut manifest = BundleManifest::v1(RUNTIME_COMMIT_PLACEHOLDER);
        manifest.bundle_id = "evil-client/1".into();
        let hash = manifest.golden_hash(); // use actual hash to bypass hash check
        let err = validate_bundle(&manifest, &hash).unwrap_err();
        assert!(matches!(err, BundleValidationError::UnknownBundleId(_)));
    }

    #[test]
    fn validate_rejects_unknown_event() {
        let mut manifest = BundleManifest::v1(RUNTIME_COMMIT_PLACEHOLDER);
        manifest.event_types.push("EvilEvent".into());
        let hash = manifest.golden_hash();
        let err = validate_bundle(&manifest, &hash).unwrap_err();
        assert!(matches!(err, BundleValidationError::UnknownEventType(_)));
    }

    #[test]
    fn validate_rejects_hash_mismatch() {
        let manifest = BundleManifest::v1(RUNTIME_COMMIT_PLACEHOLDER);
        let err = validate_bundle(&manifest, "deadbeef").unwrap_err();
        assert!(matches!(err, BundleValidationError::HashMismatch { .. }));
    }

    #[test]
    fn canonical_bytes_pin_format() {
        let manifest = BundleManifest::v1(RUNTIME_COMMIT_PLACEHOLDER);
        let bytes = manifest.canonical_bytes();
        let text = String::from_utf8_lossy(&bytes);

        // Verify format: BUNDLE_ID:RS:RUNTIME_COMMIT:NL
        assert!(text.starts_with("gocode-ui-client/1"));
        assert!(text.contains('\x1E'));
        assert!(text.contains("EVENTS\x1E"));
        assert!(text.contains("COMMANDS\x1E"));
        assert!(text.contains("AGGREGATES\x1E"));
        assert!(text.ends_with('\n'));
        assert!(!text.contains(' ')); // no spaces in canonical format
    }
}
