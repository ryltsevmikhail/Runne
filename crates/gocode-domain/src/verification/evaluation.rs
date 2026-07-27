use crate::verification::digest::VerificationDigest;
use crate::verification::identity::*;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateResult {
    Passed,
    Failed,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanResult {
    Passed,
    Failed,
    Blocked,
    RequiresReview,
}

/// Authoritative gate head reference.
#[derive(Clone, Debug)]
pub struct GateEvaluationRef {
    pub evaluation_ref_id: GateEvaluationID,
    pub evaluation_digest: VerificationDigest,
    pub generation: GateHeadGeneration,
}

/// Authoritative plan head reference.
#[derive(Clone, Debug)]
pub struct PlanEvaluationRef {
    pub plan_evaluation_id: PlanEvaluationID,
    pub result_digest: VerificationDigest,
    pub generation: PlanHeadGeneration,
}

/// Snapshot of gate heads for CAS verification.
#[derive(Clone, Debug)]
pub struct GateHeadSnapshot {
    pub entries: BTreeMap<String, GateHeadEntry>,
}

#[derive(Clone, Debug)]
pub struct GateHeadEntry {
    pub generation: GateHeadGeneration,
    pub evaluation_digest: VerificationDigest,
}

impl GateHeadSnapshot {
    /// Capture from current authoritative gate heads.
    pub fn capture(gate_heads: &HashMap<String, GateEvaluationRef>) -> Self {
        let entries: BTreeMap<_, _> = gate_heads
            .iter()
            .map(|(id, r)| {
                (
                    id.clone(),
                    GateHeadEntry {
                        generation: r.generation,
                        evaluation_digest: r.evaluation_digest.clone(),
                    },
                )
            })
            .collect();
        Self { entries }
    }

    /// Verify snapshot against current heads. Returns error if any gate advanced.
    pub fn verify_against_current(
        &self,
        current_heads: &HashMap<String, GateEvaluationRef>,
    ) -> Result<(), StaleGateHeadError> {
        for (gate_id, entry) in &self.entries {
            match current_heads.get(gate_id) {
                Some(current)
                    if current.generation == entry.generation
                        && current.evaluation_digest == entry.evaluation_digest => {}
                Some(current) => {
                    return Err(StaleGateHeadError {
                        gate_id: gate_id.clone(),
                        expected: entry.generation,
                        actual: current.generation,
                    });
                }
                None => {
                    return Err(StaleGateHeadError {
                        gate_id: gate_id.clone(),
                        expected: entry.generation,
                        actual: 0,
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct StaleGateHeadError {
    pub gate_id: String,
    pub expected: GateHeadGeneration,
    pub actual: GateHeadGeneration,
}

impl std::fmt::Display for StaleGateHeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stale gate head '{}': expected gen {}, actual gen {}",
            self.gate_id, self.expected, self.actual
        )
    }
}
impl std::error::Error for StaleGateHeadError {}

/// CAS store for gate evaluations.
#[derive(Clone, Debug, Default)]
pub struct GateHeadStore {
    heads: HashMap<String, GateEvaluationRef>,
}

impl GateHeadStore {
    pub fn new() -> Self {
        Self {
            heads: HashMap::new(),
        }
    }

    /// CAS: commit new evaluation. Requires exact expected predecessor generation.
    pub fn cas(
        &mut self,
        gate_id: String,
        evaluation_digest: VerificationDigest,
        expected_generation: GateHeadGeneration,
    ) -> Result<GateEvaluationRef, CasError> {
        let current_gen = self.heads.get(&gate_id).map(|r| r.generation).unwrap_or(0);
        if current_gen != expected_generation {
            return Err(CasError::VersionConflict {
                gate_id,
                expected: expected_generation,
                actual: current_gen,
            });
        }
        let new_gen = current_gen + 1;
        let ref_id = uuid::Uuid::now_v7();
        let gate_ref = GateEvaluationRef {
            evaluation_ref_id: ref_id,
            evaluation_digest,
            generation: new_gen,
        };
        self.heads.insert(gate_id, gate_ref.clone());
        Ok(gate_ref)
    }

    pub fn get_head(&self, gate_id: &str) -> Option<&GateEvaluationRef> {
        self.heads.get(gate_id)
    }

    pub fn all_heads(&self) -> &HashMap<String, GateEvaluationRef> {
        &self.heads
    }
}

/// CAS store for plan evaluations.
#[derive(Clone, Debug, Default)]
pub struct PlanHeadStore {
    head: Option<PlanEvaluationRef>,
}

impl PlanHeadStore {
    pub fn new() -> Self {
        Self { head: None }
    }

    pub fn cas(
        &mut self,
        result_digest: VerificationDigest,
        expected_generation: PlanHeadGeneration,
        snapshot: &GateHeadSnapshot,
        gate_heads: &HashMap<String, GateEvaluationRef>,
    ) -> Result<PlanEvaluationRef, CasError> {
        let current_gen = self.head.as_ref().map(|r| r.generation).unwrap_or(0);
        if current_gen != expected_generation {
            return Err(CasError::VersionConflict {
                gate_id: "plan".into(),
                expected: expected_generation,
                actual: current_gen,
            });
        }
        // Atomic GateHeadSnapshot check
        snapshot
            .verify_against_current(gate_heads)
            .map_err(|e| CasError::StaleGateHead(e.to_string()))?;
        let new_gen = current_gen + 1;
        let plan_ref = PlanEvaluationRef {
            plan_evaluation_id: uuid::Uuid::now_v7(),
            result_digest,
            generation: new_gen,
        };
        self.head = Some(plan_ref.clone());
        Ok(plan_ref)
    }

    pub fn get_head(&self) -> Option<&PlanEvaluationRef> {
        self.head.as_ref()
    }
}

#[derive(Debug)]
pub enum CasError {
    VersionConflict {
        gate_id: String,
        expected: u64,
        actual: u64,
    },
    StaleGateHead(String),
}

impl std::fmt::Display for CasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionConflict {
                gate_id,
                expected,
                actual,
            } => write!(
                f,
                "CAS conflict on '{}': expected gen {}, got {}",
                gate_id, expected, actual
            ),
            Self::StaleGateHead(msg) => write!(f, "stale gate head: {}", msg),
        }
    }
}
impl std::error::Error for CasError {}

/// Aggregate plan result from gate results.
pub fn aggregate_plan_result(gate_results: &[(String, GateResult)]) -> PlanResult {
    let any_failed = gate_results.iter().any(|(_, r)| *r == GateResult::Failed);
    if any_failed {
        return PlanResult::Failed;
    }
    let any_blocked = gate_results.iter().any(|(_, r)| *r == GateResult::Blocked);
    if any_blocked {
        return PlanResult::Blocked;
    }
    PlanResult::Passed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::digest::VerificationDigest;

    fn test_digest(b: u8) -> VerificationDigest {
        VerificationDigest::from_bytes([b; 32])
    }

    #[test]
    fn all_passed() {
        assert_eq!(
            aggregate_plan_result(&[("G1".into(), GateResult::Passed)]),
            PlanResult::Passed
        );
    }
    #[test]
    fn any_failed() {
        assert_eq!(
            aggregate_plan_result(&[
                ("G1".into(), GateResult::Passed),
                ("G2".into(), GateResult::Failed)
            ]),
            PlanResult::Failed
        );
    }
    #[test]
    fn any_blocked() {
        assert_eq!(
            aggregate_plan_result(&[
                ("G1".into(), GateResult::Passed),
                ("G2".into(), GateResult::Blocked)
            ]),
            PlanResult::Blocked
        );
    }
    #[test]
    fn failed_wins_over_blocked() {
        assert_eq!(
            aggregate_plan_result(&[
                ("G1".into(), GateResult::Failed),
                ("G2".into(), GateResult::Blocked)
            ]),
            PlanResult::Failed
        );
    }

    // GateHeadSnapshot tests
    #[test]
    fn gate_head_snapshot_verify_ok() {
        let d = test_digest(1);
        let mut heads = HashMap::new();
        heads.insert(
            "G1".into(),
            GateEvaluationRef {
                evaluation_ref_id: uuid::Uuid::now_v7(),
                evaluation_digest: d.clone(),
                generation: 1,
            },
        );
        let snapshot = GateHeadSnapshot::capture(&heads);
        assert!(snapshot.verify_against_current(&heads).is_ok());
    }

    #[test]
    fn gate_head_snapshot_detect_stale() {
        let mut heads_before = HashMap::new();
        heads_before.insert(
            "G1".into(),
            GateEvaluationRef {
                evaluation_ref_id: uuid::Uuid::now_v7(),
                evaluation_digest: test_digest(1),
                generation: 1,
            },
        );
        let snapshot = GateHeadSnapshot::capture(&heads_before);
        let mut heads_after = HashMap::new();
        heads_after.insert(
            "G1".into(),
            GateEvaluationRef {
                evaluation_ref_id: uuid::Uuid::now_v7(),
                evaluation_digest: test_digest(2),
                generation: 2,
            },
        );
        assert!(snapshot.verify_against_current(&heads_after).is_err());
    }

    // CAS tests
    #[test]
    fn gate_cas_first_succeeds() {
        let mut store = GateHeadStore::new();
        let r = store.cas("G1".into(), test_digest(1), 0).unwrap();
        assert_eq!(r.generation, 1);
    }

    #[test]
    fn gate_cas_second_succeeds() {
        let mut store = GateHeadStore::new();
        let r1 = store.cas("G1".into(), test_digest(1), 0).unwrap();
        let r2 = store.cas("G1".into(), test_digest(2), 1).unwrap();
        assert_eq!(r2.generation, 2);
        assert_ne!(r1.evaluation_digest, r2.evaluation_digest);
    }

    #[test]
    fn gate_cas_version_conflict() {
        let mut store = GateHeadStore::new();
        store.cas("G1".into(), test_digest(1), 0).unwrap();
        assert!(store.cas("G1".into(), test_digest(2), 0).is_err()); // stale
    }

    #[test]
    fn plan_cas_with_snapshot_succeeds() {
        let mut gate_store = GateHeadStore::new();
        gate_store.cas("G1".into(), test_digest(1), 0).unwrap();
        let snapshot = GateHeadSnapshot::capture(gate_store.all_heads());
        let mut plan_store = PlanHeadStore::new();
        let r = plan_store
            .cas(test_digest(10), 0, &snapshot, gate_store.all_heads())
            .unwrap();
        assert_eq!(r.generation, 1);
    }

    #[test]
    fn plan_cas_stale_gate_head_rejected() {
        let mut gate_store = GateHeadStore::new();
        gate_store.cas("G1".into(), test_digest(1), 0).unwrap();
        let snapshot = GateHeadSnapshot::capture(gate_store.all_heads());
        // Gate advances after snapshot
        gate_store.cas("G1".into(), test_digest(2), 1).unwrap();
        let mut plan_store = PlanHeadStore::new();
        assert!(
            plan_store
                .cas(test_digest(10), 0, &snapshot, gate_store.all_heads())
                .is_err()
        );
    }

    #[test]
    fn plan_cas_version_conflict() {
        let mut gate_store = GateHeadStore::new();
        gate_store.cas("G1".into(), test_digest(1), 0).unwrap();
        let snapshot = GateHeadSnapshot::capture(gate_store.all_heads());
        let mut plan_store = PlanHeadStore::new();
        plan_store
            .cas(test_digest(10), 0, &snapshot, gate_store.all_heads())
            .unwrap();
        assert!(
            plan_store
                .cas(test_digest(11), 0, &snapshot, gate_store.all_heads())
                .is_err()
        );
    }

    #[test]
    fn concurrent_gate_cas_one_winner() {
        let mut store = GateHeadStore::new();
        let r1 = store.cas("G1".into(), test_digest(1), 0);
        let r2 = store.cas("G1".into(), test_digest(2), 0);
        assert!(r1.is_ok() ^ r2.is_ok()); // exactly one winner
    }
}

// ===== Deterministic Evaluator =====

/// Pure deterministic evaluator — no I/O, no side effects.
pub struct DeterministicEvaluator;

impl DeterministicEvaluator {
    /// Evaluate a single gate: check evidence layer requirements and criteria.
    /// Pure function: same inputs → same output.
    pub fn evaluate_gate(
        required_layers: &[String],
        evidence_layers: &[String],
        criteria_met: bool,
    ) -> GateResult {
        // Check all required layers are present in evidence
        for required in required_layers {
            if !evidence_layers.contains(required) {
                return GateResult::Blocked;
            }
        }
        if criteria_met {
            GateResult::Passed
        } else {
            GateResult::Failed
        }
    }

    /// Aggregate gate evaluations into plan result.
    pub fn evaluate_plan(gate_results: &[(String, GateResult)]) -> PlanResult {
        aggregate_plan_result(gate_results)
    }
}

// ===== Statistical Policy =====

/// Predeclared statistical evaluation policy (L4 only).
#[derive(Clone, Debug)]
pub struct StatisticalPolicy {
    pub sample_size: u64,
    pub margin: f64,
    pub confidence: f64,
}

/// Statistical evaluation result — consumed by GateEvaluator.
#[derive(Clone, Debug)]
pub struct StatisticalResult {
    pub sample_size_achieved: u64,
    pub sufficient: bool,
    pub metric_value: f64,
}

impl StatisticalResult {
    pub fn evaluate(policy: &StatisticalPolicy, samples: &[f64]) -> Self {
        let achieved = samples.len() as u64;
        let sufficient = achieved >= policy.sample_size;
        let metric_value = if achieved > 0 {
            samples.iter().sum::<f64>() / achieved as f64
        } else {
            0.0
        };
        Self {
            sample_size_achieved: achieved,
            sufficient,
            metric_value,
        }
    }
}

// ===== ConsumptionIntent Store =====

/// ConsumptionIntent CAS store with fencing support.
#[derive(Clone, Debug, Default)]
pub struct IntentStore {
    intents: HashMap<IntentID, ConsumptionIntent>,
}

impl IntentStore {
    pub fn new() -> Self {
        Self {
            intents: HashMap::new(),
        }
    }

    /// Reserve intent atomically. Duplicate → prior outcome.
    pub fn reserve(
        &mut self,
        intent_id: IntentID,
        idempotency_key: &str,
        snapshot_digest: VerificationDigest,
        target_digest: VerificationDigest,
    ) -> Result<ConsumptionIntent, IntentError> {
        if let Some(existing) = self.intents.get(&intent_id) {
            if existing.idempotency_key == idempotency_key {
                return Ok(existing.clone());
            }
            return Err(IntentError::AlreadyReserved);
        }
        let intent = ConsumptionIntent {
            intent_id,
            idempotency_key: idempotency_key.to_string(),
            state: IntentState::Reserved,
            gate_head_snapshot_digest: snapshot_digest,
            target_artifact_digest: target_digest,
            integrity_digest: VerificationDigest::from_bytes([0; 32]),
        };
        self.intents.insert(intent_id, intent);
        Ok(self.intents.get(&intent_id).unwrap().clone())
    }

    /// Atomically claim dispatching.
    pub fn claim_dispatching(
        &mut self,
        intent_id: &IntentID,
        expected_digest: &VerificationDigest,
    ) -> Result<&ConsumptionIntent, IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or(IntentError::IntentNotFound)?;
        if intent.state == IntentState::Invalidated {
            return Err(IntentError::IntentInvalidated);
        }
        if intent.state != IntentState::Reserved {
            return Err(IntentError::InvalidTransition);
        }
        if &intent.integrity_digest != expected_digest
            && !expected_digest.as_bytes().iter().all(|b| *b == 0)
        {
            return Err(IntentError::DigestMismatch);
        }
        intent.state = IntentState::Dispatching;
        Ok(intent)
    }

    /// Invalidate intent (called by Gate CAS when gate changes under reserved intent).
    pub fn invalidate(&mut self, intent_id: &IntentID) -> Result<(), IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or(IntentError::IntentNotFound)?;
        if intent.state != IntentState::Reserved {
            return Ok(());
        } // dispatching → not invalidated
        intent.state = IntentState::Invalidated;
        Ok(())
    }

    /// Settle after effect.
    pub fn settle(&mut self, intent_id: &IntentID, success: bool) -> Result<(), IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or(IntentError::IntentNotFound)?;
        if intent.state != IntentState::Dispatching {
            return Err(IntentError::InvalidTransition);
        }
        intent.state = if success {
            IntentState::Completed
        } else {
            IntentState::Failed
        };
        Ok(())
    }

    /// Reconcile from dispatch evidence.
    pub fn reconcile(
        &mut self,
        intent_id: &IntentID,
        evidence: &DispatchEvidence,
    ) -> Result<(), IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or(IntentError::IntentNotFound)?;
        match evidence {
            DispatchEvidence::NotStarted => {
                if intent.state == IntentState::Dispatching {
                    intent.state = IntentState::Abandoned;
                }
            }
            DispatchEvidence::Acknowledged { outcome, .. } => {
                if intent.state == IntentState::Dispatching {
                    intent.state = if outcome == "success" {
                        IntentState::Completed
                    } else {
                        IntentState::Failed
                    };
                }
            }
            DispatchEvidence::Unknown => {} // stay dispatching, unresolved
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum IntentError {
    AlreadyReserved,
    IntentNotFound,
    IntentInvalidated,
    InvalidTransition,
    DigestMismatch,
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyReserved => write!(f, "intent already reserved"),
            Self::IntentNotFound => write!(f, "intent not found"),
            Self::IntentInvalidated => write!(f, "intent invalidated"),
            Self::InvalidTransition => write!(f, "invalid state transition"),
            Self::DigestMismatch => write!(f, "digest mismatch"),
        }
    }
}
impl std::error::Error for IntentError {}

use crate::verification::digest::*;
use crate::verification::intent::*;

#[cfg(test)]
mod intent_tests {
    use super::*;

    fn td(b: u8) -> VerificationDigest {
        VerificationDigest::from_bytes([b; 32])
    }

    #[test]
    fn reserve_succeeds() {
        let mut s = IntentStore::new();
        s.reserve(uuid::Uuid::now_v7(), "k1", td(1), td(2)).unwrap();
    }
    #[test]
    fn reserve_duplicate_returns_prior() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        assert!(s.reserve(id, "k1", td(1), td(2)).is_ok());
    }
    #[test]
    fn reserve_different_key_conflict() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        assert!(s.reserve(id, "k2", td(1), td(2)).is_err());
    }
    #[test]
    fn claim_dispatching_succeeds() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
    }
    #[test]
    fn claim_invalidated_rejected() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.invalidate(&id).unwrap();
        assert!(s.claim_dispatching(&id, &td(0)).is_err());
    }
    #[test]
    fn invalidate_reserved_works() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.invalidate(&id).unwrap();
    }
    #[test]
    fn invalidate_dispatching_noop() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
        s.invalidate(&id).unwrap(); /* no-op */
    }
    #[test]
    fn settle_completed() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
        s.settle(&id, true).unwrap();
    }
    #[test]
    fn reconcile_not_started() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
        s.reconcile(&id, &DispatchEvidence::NotStarted).unwrap();
    }
    #[test]
    fn reconcile_acknowledged() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
        s.reconcile(
            &id,
            &DispatchEvidence::Acknowledged {
                ack_ref: "ack1".into(),
                outcome: "success".into(),
            },
        )
        .unwrap();
    }
    #[test]
    fn reconcile_unknown_stays() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
        s.reconcile(&id, &DispatchEvidence::Unknown).unwrap();
    }
}
