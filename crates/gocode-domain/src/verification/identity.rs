//! Verification identity types — UUIDv7-based identifiers.

use uuid::Uuid;

/// Verification plan identity.
pub type PlanID = Uuid;

/// Verification run identity.
pub type RunID = Uuid;

/// Evaluation profile identity.
pub type ProfileID = Uuid;

/// Evidence item reference identity.
pub type EvidenceRefID = Uuid;

/// Gate evaluation identity.
pub type GateEvaluationID = Uuid;

/// Plan evaluation identity.
pub type PlanEvaluationID = Uuid;

/// Live evaluation authorization identity.
pub type AuthorizationID = Uuid;

/// Consumption intent identity.
pub type IntentID = Uuid;

/// Backup identity.
pub type BackupID = Uuid;

/// Gate head monotonic generation counter.
pub type GateHeadGeneration = u64;

/// Plan head monotonic generation counter.
pub type PlanHeadGeneration = u64;

/// Idempotency key — caller-stable, uniqueness-constrained.
pub type IdempotencyKey = String;

/// Cutover session identity.
pub type CutoverSessionID = Uuid;

/// Export document identity.
pub type ExportID = Uuid;

/// Promotion identity.
pub type PromotionID = Uuid;

/// Pruning run identity.
pub type PruningRunID = Uuid;
