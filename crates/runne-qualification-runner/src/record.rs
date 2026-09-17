use runne_native_qualification::VerifiedQualificationFenceFacts;

use crate::{CanonicalRunBinding, QualificationReplayLedgerError};

pub struct FaultRecord {
    pub context_id: [u8; 32],
    pub context_nonce: [u8; 32],
    pub ticket_id: [u8; 32],
    pub ticket_nonce: [u8; 32],
    pub fingerprint: [u8; 32],
    pub candidate: [u8; 32],
    pub raw_tuple: [u8; 32],
    pub source: [u8; 20],
    pub run: String,
    pub namespace: [u8; 32],
    pub manifest: [u8; 32],
    pub profile: [u8; 32],
}

impl FaultRecord {
    pub fn from_facts(
        facts: &VerifiedQualificationFenceFacts,
        binding: &CanonicalRunBinding,
    ) -> Result<Self, QualificationReplayLedgerError> {
        let record = Self {
            context_id: facts.context_id(),
            context_nonce: facts.context_nonce(),
            ticket_id: facts.ticket_id(),
            ticket_nonce: facts.ticket_nonce(),
            fingerprint: facts.fingerprint(),
            candidate: facts.candidate_sha256(),
            raw_tuple: facts.raw_v3_tuple_sha256(),
            source: facts.source_revision(),
            run: facts.workflow_run_id().to_owned(),
            namespace: facts.namespace_sha256(),
            manifest: binding.manifest_sha256(),
            profile: binding.profile_sha256(),
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
            self.ticket_id,
            self.ticket_nonce,
            self.fingerprint,
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
