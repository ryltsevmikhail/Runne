//! VerificationPlan — immutable plan with revision and digest.
//! GateDefinition — immutable gate within a plan revision.

use crate::verification::digest::{DigestContract, VerificationDigest};
use crate::verification::identity::PlanID;

/// Immutable verification plan revision.
#[derive(Clone, Debug)]
pub struct VerificationPlan {
    pub plan_id: PlanID,
    pub revision: u64,
    pub integrity_digest: VerificationDigest,
    pub target: String,
    pub acceptance_criteria: String,
    pub gates: Vec<GateDefinition>,
    pub policy_revision: String,
}

impl VerificationPlan {
    /// Create first revision of a plan.
    pub fn new(
        plan_id: PlanID,
        target: String,
        acceptance_criteria: String,
        gates: Vec<GateDefinition>,
        policy_revision: String,
    ) -> Self {
        let revision = 1;
        let integrity_digest = Self::compute_digest(
            plan_id, revision, &target, &acceptance_criteria, &gates, &policy_revision,
        );
        Self { plan_id, revision, integrity_digest, target, acceptance_criteria, gates, policy_revision }
    }

    /// Create next revision (consumes self to prevent mutation of committed plan).
    pub fn next_revision(
        self,
        target: String,
        acceptance_criteria: String,
        gates: Vec<GateDefinition>,
        policy_revision: String,
    ) -> Self {
        let revision = self.revision + 1;
        let integrity_digest = Self::compute_digest(
            self.plan_id, revision, &target, &acceptance_criteria, &gates, &policy_revision,
        );
        Self { plan_id: self.plan_id, revision, integrity_digest, target, acceptance_criteria, gates, policy_revision }
    }

    fn compute_digest(
        plan_id: PlanID,
        revision: u64,
        target: &str,
        acceptance_criteria: &str,
        gates: &[GateDefinition],
        policy_revision: &str,
    ) -> VerificationDigest {
        let contract = DigestContract::new("gocode:verification-plan:v1");
        let mut components: Vec<Vec<u8>> = Vec::new();
        components.push(plan_id.as_bytes().to_vec());
        components.push(revision.to_be_bytes().to_vec());
        components.push(target.as_bytes().to_vec());
        components.push(acceptance_criteria.as_bytes().to_vec());
        for gate in gates {
            components.push(gate.definition_digest.as_bytes().to_vec());
        }
        components.push(policy_revision.as_bytes().to_vec());
        let slices: Vec<&[u8]> = components.iter().map(|v| v.as_slice()).collect();
        contract.compute(&slices)
    }
}

/// Immutable gate definition within a plan revision.
#[derive(Clone, Debug)]
pub struct GateDefinition {
    pub gate_id: String,
    pub definition_digest: VerificationDigest,
    pub criteria: String,
    pub required_evidence_layers: Vec<String>,
    pub dependencies: Vec<String>,
}

impl GateDefinition {
    pub fn new(
        gate_id: String,
        criteria: String,
        required_evidence_layers: Vec<String>,
        dependencies: Vec<String>,
    ) -> Result<Self, PlanError> {
        // Validate no self-dependency
        if dependencies.contains(&gate_id) {
            return Err(PlanError::SelfDependency(gate_id));
        }
        let definition_digest = Self::compute_definition_digest(
            &gate_id, &criteria, &required_evidence_layers, &dependencies,
        );
        Ok(Self { gate_id, definition_digest, criteria, required_evidence_layers, dependencies })
    }

    fn compute_definition_digest(
        gate_id: &str,
        criteria: &str,
        layers: &[String],
        deps: &[String],
    ) -> VerificationDigest {
        let contract = DigestContract::new("gocode:gate-definition:v1");
        let mut components: Vec<Vec<u8>> = Vec::new();
        components.push(gate_id.as_bytes().to_vec());
        components.push(criteria.as_bytes().to_vec());
        for layer in layers {
            components.push(layer.as_bytes().to_vec());
        }
        for dep in deps {
            components.push(dep.as_bytes().to_vec());
        }
        let slices: Vec<&[u8]> = components.iter().map(|v| v.as_slice()).collect();
        contract.compute(&slices)
    }
}

/// Compute gate dependency graph — detect circular dependencies.
pub fn validate_gate_dependencies(gates: &[GateDefinition]) -> Result<(), PlanError> {
    for gate in gates {
        for dep in &gate.dependencies {
            if !gates.iter().any(|g| g.gate_id == *dep) {
                return Err(PlanError::MissingDependency(gate.gate_id.clone(), dep.clone()));
            }
        }
    }
    // Simple cycle detection via DFS
    for gate in gates {
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![&gate.gate_id];
        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(g) = gates.iter().find(|g| &g.gate_id == current) {
                for dep in &g.dependencies {
                    if dep == &gate.gate_id {
                        return Err(PlanError::CircularDependency(gate.gate_id.clone()));
                    }
                    stack.push(dep);
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    SelfDependency(String),
    MissingDependency(String, String),
    CircularDependency(String),
    EmptyGates,
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SelfDependency(id) => write!(f, "gate '{}' cannot depend on itself", id),
            Self::MissingDependency(gate, dep) => write!(f, "gate '{}' depends on missing gate '{}'", gate, dep),
            Self::CircularDependency(id) => write!(f, "circular dependency involving gate '{}'", id),
            Self::EmptyGates => write!(f, "plan must have at least one gate"),
        }
    }
}

impl std::error::Error for PlanError {}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn create_plan_with_gates() {
        let gate = GateDefinition::new("G1".into(), "pass all tests".into(), vec!["L0".into()], vec![]).unwrap();
        let plan = VerificationPlan::new(
            Uuid::now_v7(), "subsystem-x".into(), "all gates pass".into(),
            vec![gate], "v1".into(),
        );
        assert_eq!(plan.revision, 1);
        assert_eq!(plan.gates.len(), 1);
    }

    #[test]
    fn plan_revision_is_immutable_after_next() {
        let gate = GateDefinition::new("G1".into(), "criteria".into(), vec![], vec![]).unwrap();
        let plan_v1 = VerificationPlan::new(
            Uuid::now_v7(), "target".into(), "accept".into(),
            vec![gate.clone()], "v1".into(),
        );
        let digest_v1 = plan_v1.integrity_digest.clone();
        let plan_v2 = plan_v1.next_revision("target2".into(), "accept2".into(), vec![gate], "v2".into());
        assert_eq!(plan_v2.revision, 2);
        assert_ne!(digest_v1.to_hex(), plan_v2.integrity_digest.to_hex()); // just verify digest exists
    }

    #[test]
    fn gate_definition_digest_is_stable() {
        let g1 = GateDefinition::new("G1".into(), "criteria".into(), vec![], vec![]).unwrap();
        let g2 = GateDefinition::new("G1".into(), "criteria".into(), vec![], vec![]).unwrap();
        assert_eq!(g1.definition_digest, g2.definition_digest);
    }

    #[test]
    fn gate_self_dependency_rejected() {
        assert!(GateDefinition::new("G1".into(), "c".into(), vec![], vec!["G1".into()]).is_err());
    }

    #[test]
    fn gate_circular_dependency_rejected() {
        let g1 = GateDefinition::new("G1".into(), "c".into(), vec![], vec!["G2".into()]).unwrap();
        let g2 = GateDefinition::new("G2".into(), "c".into(), vec![], vec!["G1".into()]).unwrap();
        assert!(validate_gate_dependencies(&[g1, g2]).is_err());
    }

    #[test]
    fn gate_missing_prerequisite_rejected() {
        let g1 = GateDefinition::new("G1".into(), "c".into(), vec![], vec!["G2".into()]).unwrap();
        assert!(validate_gate_dependencies(&[g1]).is_err());
    }

    #[test]
    fn valid_dependencies_pass() {
        let g1 = GateDefinition::new("G1".into(), "c".into(), vec![], vec![]).unwrap();
        let g2 = GateDefinition::new("G2".into(), "c".into(), vec![], vec!["G1".into()]).unwrap();
        assert!(validate_gate_dependencies(&[g1, g2]).is_ok());
    }
}
