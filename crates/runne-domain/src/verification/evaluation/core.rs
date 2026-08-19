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
