//! Canonical digest types and domain-separated digest contracts.
//! SHA-256 only for v1.

use sha2::{Digest as _, Sha256};
use std::fmt;

/// SHA-256 digest — 32 bytes, lowercase hex representation (64 chars).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VerificationDigest([u8; 32]);

impl VerificationDigest {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse from 64-char lowercase hex string.
    pub fn from_hex(hex: &str) -> Result<Self, DigestError> {
        if hex.len() != 64 {
            return Err(DigestError::InvalidLength(hex.len()));
        }
        if hex.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(DigestError::UppercaseHex);
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex, &mut bytes)
            .map_err(|_| DigestError::InvalidHex)?;
        Ok(Self(bytes))
    }

    /// Format as 64-char lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for VerificationDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerificationDigest({})", self.to_hex())
    }
}

impl fmt::Display for VerificationDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Domain-separated digest contract.
pub struct DigestContract {
    domain_tag: &'static str,
}

impl DigestContract {
    /// Create a new contract with a domain tag (e.g. "gocode:evidence-set:v1").
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
        refs: &[(crate::verification::identity::EvidenceRefID, VerificationDigest)],
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
    pub fn compute_gate_evaluation(
        &self,
        definition_digest: &VerificationDigest,
        run_id_bytes: &[u8],
        profile_digest: &VerificationDigest,
        policy_revision: &str,
        evidence_set_digest: &VerificationDigest,
        result: &str,
        reason: &str,
        predecessor_ref_bytes: &[u8],
        head_generation: u64,
    ) -> VerificationDigest {
        let mut components: Vec<&[u8]> = Vec::new();
        let mut tmp;

        components.push(definition_digest.as_bytes());
        components.push(run_id_bytes);
        components.push(profile_digest.as_bytes());
        components.push(policy_revision.as_bytes());
        components.push(evidence_set_digest.as_bytes());
        components.push(result.as_bytes());
        components.push(reason.as_bytes());
        components.push(predecessor_ref_bytes);
        tmp = head_generation.to_be_bytes();
        components.push(&tmp);

        self.compute(&components)
    }

    /// Compute plan evaluation digest.
    pub fn compute_plan_evaluation(
        &self,
        run_id_bytes: &[u8],
        profile_digest: &VerificationDigest,
        plan_binding_bytes: &[u8],
        gate_refs_canonical_bytes: &[u8],
        gate_head_snapshot_digest: &VerificationDigest,
        policy_revision: &str,
        result: &str,
        reason: &str,
        predecessor_ref_bytes: &[u8],
        head_generation: u64,
    ) -> VerificationDigest {
        let mut components: Vec<&[u8]> = Vec::new();
        let mut tmp;

        components.push(run_id_bytes);
        components.push(profile_digest.as_bytes());
        components.push(plan_binding_bytes);
        components.push(gate_refs_canonical_bytes);
        components.push(gate_head_snapshot_digest.as_bytes());
        components.push(policy_revision.as_bytes());
        components.push(result.as_bytes());
        components.push(reason.as_bytes());
        components.push(predecessor_ref_bytes);
        tmp = head_generation.to_be_bytes();
        components.push(&tmp);

        self.compute(&components)
    }
}

/// Digest computation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// Hex string has wrong length (must be 64 chars).
    InvalidLength(usize),
    /// Hex string contains uppercase characters.
    UppercaseHex,
    /// Invalid hex characters.
    InvalidHex,
    /// Duplicate evidence ref in set.
    DuplicateEvidenceRef(crate::verification::identity::EvidenceRefID),
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(n) => write!(f, "invalid digest length: {} (expected 64)", n),
            Self::UppercaseHex => write!(f, "uppercase hex not allowed"),
            Self::InvalidHex => write!(f, "invalid hex characters"),
            Self::DuplicateEvidenceRef(id) => write!(f, "duplicate evidence ref: {}", id),
        }
    }
}

impl std::error::Error for DigestError {}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn digest_from_valid_hex() {
        let hex = "a".repeat(64);
        let d = VerificationDigest::from_hex(&hex).unwrap();
        assert_eq!(d.to_hex(), hex);
    }

    #[test]
    fn digest_from_invalid_hex_rejects() {
        assert!(VerificationDigest::from_hex("gg".repeat(32).as_str()).is_err());
    }

    #[test]
    fn digest_from_wrong_length_rejects() {
        assert!(VerificationDigest::from_hex("abc").is_err());
    }

    #[test]
    fn digest_from_uppercase_rejects() {
        assert!(VerificationDigest::from_hex("A".repeat(64).as_str()).is_err());
    }

    #[test]
    fn evidence_set_digest_is_deterministic() {
        let contract = DigestContract::new("gocode:evidence-set:v1");
        let id1 = Uuid::now_v7();
        let id2 = Uuid::now_v7();
        let d1 = VerificationDigest::from_bytes([1u8; 32]);
        let d2 = VerificationDigest::from_bytes([2u8; 32]);

        let refs = vec![(id1, d1.clone()), (id2, d2.clone())];
        let result1 = contract.compute_evidence_set(&refs).unwrap();
        let result2 = contract.compute_evidence_set(&refs).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn evidence_set_digest_changes_with_content() {
        let contract = DigestContract::new("gocode:evidence-set:v1");
        let id1 = Uuid::now_v7();
        let refs1 = vec![(id1, VerificationDigest::from_bytes([1u8; 32]))];
        let refs2 = vec![(id1, VerificationDigest::from_bytes([2u8; 32]))];

        let r1 = contract.compute_evidence_set(&refs1).unwrap();
        let r2 = contract.compute_evidence_set(&refs2).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn evidence_set_digest_same_for_different_order() {
        let contract = DigestContract::new("gocode:evidence-set:v1");
        let id1 = Uuid::now_v7();
        let id2 = Uuid::now_v7();
        let d1 = VerificationDigest::from_bytes([1u8; 32]);
        let d2 = VerificationDigest::from_bytes([2u8; 32]);

        let refs1 = vec![(id1, d1.clone()), (id2, d2.clone())];
        let refs2 = vec![(id2, d2.clone()), (id1, d1.clone())];
        assert_eq!(
            contract.compute_evidence_set(&refs1).unwrap(),
            contract.compute_evidence_set(&refs2).unwrap()
        );
    }

    #[test]
    fn duplicate_evidence_ref_rejected() {
        let contract = DigestContract::new("gocode:evidence-set:v1");
        let id = Uuid::now_v7();
        let d = VerificationDigest::from_bytes([1u8; 32]);
        let refs = vec![(id, d.clone()), (id, d.clone())];
        assert!(contract.compute_evidence_set(&refs).is_err());
    }

    #[test]
    fn empty_evidence_set_has_digest() {
        let contract = DigestContract::new("gocode:evidence-set:v1");
        let refs: Vec<(Uuid, VerificationDigest)> = vec![];
        let result = contract.compute_evidence_set(&refs).unwrap();
        // Non-zero digest even for empty set
        assert!(!result.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn domain_tag_separation() {
        let c1 = DigestContract::new("gocode:evidence-set:v1");
        let c2 = DigestContract::new("gocode:evidence-set:v2");
        let id = Uuid::now_v7();
        let d = VerificationDigest::from_bytes([1u8; 32]);
        let refs = vec![(id, d)];
        assert_ne!(c1.compute_evidence_set(&refs).unwrap(), c2.compute_evidence_set(&refs).unwrap());
    }

    #[test]
    fn gate_evaluation_digest_formula() {
        let contract = DigestContract::new("gocode:gate-evaluation:v1");
        let result = contract.compute_gate_evaluation(
            &VerificationDigest::from_bytes([1u8; 32]),
            &[2u8; 16],
            &VerificationDigest::from_bytes([3u8; 32]),
            "v1",
            &VerificationDigest::from_bytes([4u8; 32]),
            "passed",
            "all criteria met",
            &[],
            1,
        );
        assert!(!result.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn plan_evaluation_digest_formula() {
        let contract = DigestContract::new("gocode:plan-evaluation:v1");
        let result = contract.compute_plan_evaluation(
            &[1u8; 16],
            &VerificationDigest::from_bytes([2u8; 32]),
            b"plan-binding",
            b"gate-refs",
            &VerificationDigest::from_bytes([3u8; 32]),
            "v1",
            "passed",
            "all gates passed",
            &[],
            1,
        );
        assert!(!result.as_bytes().iter().all(|b| *b == 0));
    }
}
