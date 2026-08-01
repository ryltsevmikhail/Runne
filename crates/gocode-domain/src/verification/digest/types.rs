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
        hex::decode_to_slice(hex, &mut bytes).map_err(|_| DigestError::InvalidHex)?;
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

/// Canonical input for gate evaluation digest computation.
pub struct GateEvaluationInput<'a> {
    pub definition_digest: &'a VerificationDigest,
    pub run_id_bytes: &'a [u8],
    pub profile_digest: &'a VerificationDigest,
    pub policy_revision: &'a str,
    pub evidence_set_digest: &'a VerificationDigest,
    pub result: &'a str,
    pub reason: &'a str,
    pub predecessor_ref_bytes: &'a [u8],
    pub head_generation: u64,
}

/// Canonical input for plan evaluation digest computation.
pub struct PlanEvaluationInput<'a> {
    pub run_id_bytes: &'a [u8],
    pub profile_digest: &'a VerificationDigest,
    pub plan_binding_bytes: &'a [u8],
    pub gate_refs_canonical_bytes: &'a [u8],
    pub gate_head_snapshot_digest: &'a VerificationDigest,
    pub policy_revision: &'a str,
    pub result: &'a str,
    pub reason: &'a str,
    pub predecessor_ref_bytes: &'a [u8],
    pub head_generation: u64,
}
