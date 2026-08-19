/// SHA-256 digest restricted to parsed production inputs or fixture helpers.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Digest([u8; 32]);
impl Digest {
    pub(crate) const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
    #[cfg(any(test, feature = "fixture-only"))]
    #[must_use]
    pub const fn fixture(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Immutable input chain: no RC stage may substitute any one binding member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateBinding {
    subject: Digest,
    matrix: Digest,
    bootstrap: Digest,
    candidate: Digest,
    policy: Digest,
    release_facts: Option<Digest>,
    fixture: bool,
}
impl CandidateBinding {
    /// Derive a candidate commitment only from an owner-verified V4 bootstrap and canonical
    /// unsigned manifest. Callers cannot choose the RC0 subject, matrix, policy, or bootstrap.
    ///
    /// # Errors
    /// Returns an error when the manifest is not the exact RC0-bound unsigned candidate input.
    pub fn from_verified_bootstrap(
        bootstrap: &runne_project_owner_authority::VerifiedPromotionBootstrap,
        manifest: &crate::InspectedCanonicalPayload,
    ) -> Result<Self, crate::AuthorityError> {
        let bindings = bootstrap.bindings();
        let binding = Self {
            subject: Digest::from_bytes(bindings.subject_sha256()),
            matrix: Digest::from_bytes(bindings.matrix_sha256()),
            bootstrap: Digest::from_bytes(bootstrap.receipt_sha256()),
            candidate: manifest
                .candidate_digest()
                .ok_or(crate::AuthorityError::BindingMismatch)?,
            policy: Digest::from_bytes(bindings.policy_sha256()),
            release_facts: Some(manifest.raw_digest()),
            fixture: true,
        };
        if manifest.kind() != crate::CanonicalPayloadKind::UnsignedManifest
            || !manifest.matches_binding(&binding)
        {
            return Err(crate::AuthorityError::BindingMismatch);
        }
        Ok(binding)
    }
    #[cfg(any(test, feature = "fixture-only"))]
    #[must_use]
    pub const fn fixture(
        subject: [u8; 32],
        matrix: [u8; 32],
        bootstrap: [u8; 32],
        candidate: [u8; 32],
        policy: [u8; 32],
    ) -> Self {
        Self {
            subject: Digest::fixture(subject),
            matrix: Digest::fixture(matrix),
            bootstrap: Digest::fixture(bootstrap),
            candidate: Digest::fixture(candidate),
            policy: Digest::fixture(policy),
            release_facts: None,
            fixture: true,
        }
    }
    #[cfg(any(test, feature = "fixture-only"))]
    #[must_use]
    pub const fn fixture_with_release_facts(
        subject: [u8; 32],
        matrix: [u8; 32],
        bootstrap: [u8; 32],
        candidate: [u8; 32],
        policy: [u8; 32],
        release_facts: [u8; 32],
    ) -> Self {
        Self {
            subject: Digest::fixture(subject),
            matrix: Digest::fixture(matrix),
            bootstrap: Digest::fixture(bootstrap),
            candidate: Digest::fixture(candidate),
            policy: Digest::fixture(policy),
            release_facts: Some(Digest::fixture(release_facts)),
            fixture: true,
        }
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) const fn from_durable_components(
        subject: Digest,
        matrix: Digest,
        bootstrap: Digest,
        candidate: Digest,
        policy: Digest,
        release_facts: Option<Digest>,
    ) -> Self {
        Self {
            subject,
            matrix,
            bootstrap,
            candidate,
            policy,
            release_facts,
            fixture: true,
        }
    }
    #[must_use]
    pub const fn subject(&self) -> Digest {
        self.subject
    }
    #[must_use]
    pub const fn matrix(&self) -> Digest {
        self.matrix
    }
    #[must_use]
    pub const fn bootstrap(&self) -> Digest {
        self.bootstrap
    }
    #[must_use]
    pub const fn candidate(&self) -> Digest {
        self.candidate
    }
    #[must_use]
    pub const fn policy(&self) -> Digest {
        self.policy
    }
    #[must_use]
    pub(crate) const fn release_facts(&self) -> Option<Digest> {
        self.release_facts
    }
    #[must_use]
    pub const fn is_fixture(&self) -> bool {
        self.fixture
    }

    /// SHA-256 candidate-binding commitment over immutable RC0 and release-facts digests.
    ///
    /// Preimage: `runne.release.candidate-binding/1`, NUL, then compact
    /// lexicographic JSON with exactly one trailing LF.
    #[must_use]
    pub fn sha256(&self) -> Digest {
        use sha2::{Digest as _, Sha256};

        let payload = format!(
            "{{\"bootstrap_sha256\":\"{}\",\"candidate_sha256\":\"{}\",\"matrix_sha256\":\"{}\",\"policy_sha256\":\"{}\",\"release_facts_sha256\":{},\"subject_sha256\":\"{}\"}}\n",
            self.bootstrap.to_hex(),
            self.candidate.to_hex(),
            self.matrix.to_hex(),
            self.policy.to_hex(),
            self.release_facts
                .map_or_else(|| "null".into(), |value| format!("\"{}\"", value.to_hex())),
            self.subject.to_hex(),
        );
        let mut hash = Sha256::new();
        hash.update(b"runne.release.candidate-binding/1\0");
        hash.update(payload.as_bytes());
        Digest::from_bytes(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::CandidateBinding;

    #[test]
    fn candidate_binding_digest_has_a_stable_domain_separated_vector() {
        let binding = CandidateBinding::fixture([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]);
        assert_eq!(
            binding.sha256().to_hex(),
            "84974e3df73772a649f0a22d7ec53572025ce184e63a58bc97be38b7eca6bf24"
        );
    }

    #[test]
    fn candidate_binding_digest_changes_when_any_component_changes() {
        let original = CandidateBinding::fixture([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]);
        let changed = CandidateBinding::fixture([9; 32], [2; 32], [3; 32], [4; 32], [5; 32]);
        assert_ne!(original.sha256(), changed.sha256());
    }
}
