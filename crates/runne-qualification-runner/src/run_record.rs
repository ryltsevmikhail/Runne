use runne_native_qualification::VerifiedQualificationRunBootstrapProof;

use crate::QualificationReplayLedgerError;

pub struct RunRecord {
    pub context_id: [u8; 32],
    pub context_nonce: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub challenge: [u8; 32],
    pub run_not_after: u64,
    pub fingerprint: [u8; 32],
    pub candidate: [u8; 32],
    pub raw_tuple: [u8; 32],
    pub source: [u8; 20],
    pub run: String,
    pub namespace: [u8; 32],
    pub manifest: [u8; 32],
    pub profile: [u8; 32],
}

impl RunRecord {
    pub fn from_facts(
        facts: &VerifiedQualificationRunBootstrapProof,
    ) -> Result<Self, QualificationReplayLedgerError> {
        let record = Self {
            context_id: facts.context_id(),
            context_nonce: facts.nonce(),
            issued_at: facts.issued_at(),
            expires_at: facts.expires_at(),
            challenge: facts.challenge(),
            run_not_after: facts.run_not_after(),
            fingerprint: facts.fingerprint(),
            candidate: facts.candidate_sha256(),
            raw_tuple: facts.raw_v3_tuple_sha256(),
            source: facts.source_revision(),
            run: facts.workflow_run_id().to_owned(),
            namespace: facts.namespace_sha256(),
            manifest: facts.manifest_sha256(),
            profile: facts.profile_sha256(),
        };
        record
            .valid()
            .then_some(record)
            .ok_or(QualificationReplayLedgerError)
    }

    fn valid(&self) -> bool {
        [
            self.context_id,
            self.context_nonce,
            self.fingerprint,
            self.challenge,
            self.candidate,
            self.raw_tuple,
            self.namespace,
            self.manifest,
            self.profile,
        ]
        .into_iter()
        .all(|value| value != [0; 32])
            && self.source != [0; 20]
            && self.run.len() <= 128
            && !self.run.is_empty()
            && self
                .run
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    }
}
