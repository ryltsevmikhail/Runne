//! Opaque threshold scope and acknowledgement capabilities.

use sha2::{Digest as _, Sha256};

use crate::Digest;

/// Immutable external journal identity for a threshold admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdAdmissionScope {
    pub(crate) authority_instance: Digest,
    pub(crate) promotion: String,
    pub(crate) revision: u64,
    pub(crate) command: String,
    pub(crate) authorization: Digest,
    pub(crate) commitment: Digest,
    pub(crate) candidate: Digest,
    pub(crate) inventory: Digest,
    pub(crate) metadata: Digest,
    pub(crate) report: Digest,
}

impl ThresholdAdmissionScope {
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut transcript = b"gocode.release.threshold-admission-scope/1\0".to_vec();
        append(&mut transcript, &self.authority_instance.as_bytes());
        append(&mut transcript, self.promotion.as_bytes());
        append(&mut transcript, &self.revision.to_be_bytes());
        append(&mut transcript, self.command.as_bytes());
        for digest in [
            self.authorization,
            self.commitment,
            self.candidate,
            self.inventory,
            self.metadata,
            self.report,
        ] {
            append(&mut transcript, &digest.as_bytes());
        }
        Digest::from_bytes(Sha256::digest(transcript).into())
    }
}

fn append(transcript: &mut Vec<u8>, field: &[u8]) {
    transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
    transcript.extend_from_slice(field);
}

/// Move-only store claim for one exact pending threshold delivery.
#[derive(Debug, Eq, PartialEq)]
pub struct PendingThresholdAck {
    pub(crate) admission: Digest,
    pub(crate) revision: u64,
}

impl PendingThresholdAck {
    pub(crate) const fn into_parts(self) -> (Digest, u64) {
        (self.admission, self.revision)
    }
}

/// Backend request bound to the store claim; no raw admission DTO is accepted by settlement.
pub struct ThresholdAckRequest<'a> {
    pub(crate) claim: &'a PendingThresholdAck,
}

/// Move-only backend acknowledgement that authorizes local fence settlement.
#[derive(Debug, Eq, PartialEq)]
pub struct ThresholdAckProof {
    admission: Digest,
    revision: u64,
}

impl ThresholdAckRequest<'_> {
    #[must_use]
    pub const fn admission(&self) -> Digest {
        self.claim.admission
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.claim.revision
    }

    #[must_use]
    pub const fn acknowledge(&self) -> ThresholdAckProof {
        ThresholdAckProof::from_claim(self.claim)
    }
}

impl ThresholdAckProof {
    pub(crate) fn matches(self, admission: Digest, revision: u64) -> bool {
        self.admission == admission && self.revision == revision
    }

    const fn from_claim(claim: &PendingThresholdAck) -> Self {
        Self {
            admission: claim.admission,
            revision: claim.revision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ThresholdAdmissionScope;
    use crate::Digest;

    fn scope() -> ThresholdAdmissionScope {
        ThresholdAdmissionScope {
            authority_instance: Digest::fixture([0; 32]),
            promotion: "promotion".into(),
            revision: 7,
            command: "verify".into(),
            authorization: Digest::fixture([1; 32]),
            commitment: Digest::fixture([2; 32]),
            candidate: Digest::fixture([3; 32]),
            inventory: Digest::fixture([4; 32]),
            metadata: Digest::fixture([5; 32]),
            report: Digest::fixture([6; 32]),
        }
    }

    #[test]
    fn admission_scope_digest_has_a_stable_binary_vector() {
        assert_eq!(
            scope().digest().to_hex(),
            "c67b839bef6fdb1fd2caa1713524d0bed30e09ce2823ce47228148464b6b366b"
        );
    }

    #[test]
    fn admission_scope_digest_binds_every_field() {
        let original = scope();
        let original_digest = original.digest();
        let mut cases = [
            original.clone(),
            original.clone(),
            original.clone(),
            original.clone(),
            original.clone(),
            original.clone(),
            original.clone(),
            original.clone(),
            original.clone(),
            original,
        ];
        cases[0].authority_instance = Digest::fixture([10; 32]);
        cases[1].promotion.push('x');
        cases[2].revision += 1;
        cases[3].command.push('x');
        cases[4].authorization = Digest::fixture([11; 32]);
        cases[5].commitment = Digest::fixture([12; 32]);
        cases[6].candidate = Digest::fixture([13; 32]);
        cases[7].inventory = Digest::fixture([14; 32]);
        cases[8].metadata = Digest::fixture([15; 32]);
        cases[9].report = Digest::fixture([16; 32]);
        assert!(cases.iter().all(|case| case.digest() != original_digest));
    }
}
