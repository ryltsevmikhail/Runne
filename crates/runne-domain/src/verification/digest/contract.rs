impl DigestContract {
    /// Create a new contract with a domain tag (e.g. "runne:evidence-set:v1").
    pub const fn new(domain_tag: &'static str) -> Self {
        Self { domain_tag }
    }

    /// Compute SHA-256 over domain-prefixed, length-framed components.
    pub fn compute(&self, components: &[&[u8]]) -> VerificationDigest {
        let mut hasher = Sha256::new();
        // Domain tag with length prefix
        hasher.update((self.domain_tag.len() as u64).to_be_bytes());
        hasher.update(self.domain_tag.as_bytes());
        // Each component with length prefix
        for component in components {
            hasher.update((component.len() as u64).to_be_bytes());
            hasher.update(component);
        }
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        VerificationDigest(bytes)
    }

    /// Compute evidence set digest over sorted refs.
    pub fn compute_evidence_set(
        &self,
        refs: &[(
            crate::verification::identity::EvidenceRefID,
            VerificationDigest,
        )],
    ) -> Result<VerificationDigest, DigestError> {
        // Check for duplicates
        let mut ids: Vec<_> = refs.iter().map(|(id, _)| id).collect();
        ids.sort();
        for w in ids.windows(2) {
            if w[0] == w[1] {
                return Err(DigestError::DuplicateEvidenceRef(*w[0]));
            }
        }
        // Sort by EvidenceRefID canonical bytes
        let mut sorted: Vec<_> = refs.to_vec();
        sorted.sort_by_key(|(id, _)| id.as_bytes().to_vec());

        let mut components: Vec<Vec<u8>> = Vec::new();
        for (id, digest) in &sorted {
            let mut pair = Vec::new();
            pair.extend_from_slice(id.as_bytes());
            pair.extend_from_slice(digest.as_bytes());
            components.push(pair);
        }
        let slices: Vec<&[u8]> = components.iter().map(|v| v.as_slice()).collect();
        Ok(self.compute(&slices))
    }

    /// Compute gate evaluation digest.
    pub fn compute_gate_evaluation(&self, input: &GateEvaluationInput<'_>) -> VerificationDigest {
        let tmp = input.head_generation.to_be_bytes();
        let components = vec![
            input.definition_digest.as_bytes(),
            input.run_id_bytes,
            input.profile_digest.as_bytes(),
            input.policy_revision.as_bytes(),
            input.evidence_set_digest.as_bytes(),
            input.result.as_bytes(),
            input.reason.as_bytes(),
            input.predecessor_ref_bytes,
            &tmp,
        ];

        self.compute(&components)
    }

    /// Compute plan evaluation digest.
    pub fn compute_plan_evaluation(&self, input: &PlanEvaluationInput<'_>) -> VerificationDigest {
        let tmp = input.head_generation.to_be_bytes();
        let components = vec![
            input.run_id_bytes,
            input.profile_digest.as_bytes(),
            input.plan_binding_bytes,
            input.gate_refs_canonical_bytes,
            input.gate_head_snapshot_digest.as_bytes(),
            input.policy_revision.as_bytes(),
            input.result.as_bytes(),
            input.reason.as_bytes(),
            input.predecessor_ref_bytes,
            &tmp,
        ];

        self.compute(&components)
    }
}
