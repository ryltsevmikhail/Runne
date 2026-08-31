const EVIDENCE_CHALLENGE: &[u8] =
    b"gocode/provider-credential-broker/daemon-evidence/v1/challenge\0";
const EVIDENCE_RESPONSE: &[u8] =
    b"gocode/provider-credential-broker/daemon-evidence/v1/response\0";

/// Opaque one-use proof that Desktop authenticated one exact writer tuple.
pub struct ProviderCredentialBrokerWriterEvidenceWitness {
    seal: Arc<AuthoritySeal>,
    binding: ProviderCredentialBrokerKillBindingV1,
}

/// Transfer-instance-bound writer tuple already consumed for native capture.
pub struct ProviderCredentialBrokerCapturedWriter {
    seal: Arc<AuthoritySeal>,
    binding: ProviderCredentialBrokerKillBindingV1,
}

impl ProviderCredentialBrokerTransferAuthority {
    /// Verifies both directions of the fixed daemon-evidence frame.
    pub fn verify_writer_evidence(
        &mut self,
        record: &[u8; 256],
        response_proof: &[u8; 32],
        expected_release: [u8; 32],
        expected_channel: [u8; 32],
        expected_publication_key: [u8; 32],
    ) -> Result<ProviderCredentialBrokerWriterEvidenceWitness, ProviderCredentialEnrollmentHostError>
    {
        if !std::mem::take(&mut self.writer_evidence_available) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let challenge_proof: [u8; 32] = record[96..128]
            .try_into()
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let mut challenge = EVIDENCE_CHALLENGE.to_vec();
        challenge.extend_from_slice(&record[..96]);
        let mut response = EVIDENCE_RESPONSE.to_vec();
        response.extend_from_slice(record);
        let binding = ProviderCredentialBrokerKillBindingV1::new(
            exact_32(&record[128..160])?,
            exact_32(&record[160..192])?,
            exact_32(&record[192..224])?,
            exact_32(&record[..32])?,
            exact_32(&record[32..64])?,
            exact_32(&record[224..256])?,
        );
        if !binding.valid()
            || binding.release != expected_release
            || binding.channel != expected_channel
            || binding.key != expected_publication_key
            || self.authenticate_daemon_transfer(&challenge) != challenge_proof
            || !self.verifies_desktop_transfer(&response, response_proof)
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(ProviderCredentialBrokerWriterEvidenceWitness {
            seal: Arc::clone(&self.transfer_seal),
            binding,
        })
    }

    /// Consumes evidence before any native peer authority can be captured.
    pub fn claim_writer_evidence(
        &self,
        witness: ProviderCredentialBrokerWriterEvidenceWitness,
    ) -> Result<ProviderCredentialBrokerCapturedWriter, ProviderCredentialEnrollmentHostError> {
        if !Arc::ptr_eq(&self.transfer_seal, &witness.seal) || !witness.binding.valid() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(ProviderCredentialBrokerCapturedWriter {
            seal: witness.seal,
            binding: witness.binding,
        })
    }

    /// Authenticates Ready bytes only for a captured candidate; the native
    /// crate retains the sole typed proof constructor after kernel capture.
    pub fn authenticate_kill_ready_for_captured(
        &self,
        captured: &ProviderCredentialBrokerCapturedWriter,
    ) -> Result<[u8; 32], ProviderCredentialEnrollmentHostError> {
        self.matches_captured_writer(captured)
            .then(|| {
                self.authenticator
                    .authenticate_kill_ready(&captured.binding.ready_transcript())
            })
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    #[must_use]
    pub fn verifies_kill_relinquished_for_captured(
        &self,
        proof: &ProviderCredentialBrokerKillRelinquishedProof,
        captured: &ProviderCredentialBrokerCapturedWriter,
    ) -> bool {
        self.matches_captured_writer(captured)
            && self.verifies_kill_relinquished(proof, &captured.binding)
    }

    fn matches_captured_writer(&self, captured: &ProviderCredentialBrokerCapturedWriter) -> bool {
        Arc::ptr_eq(&self.transfer_seal, &captured.seal) && captured.binding.valid()
    }
}

impl ProviderCredentialBrokerCapturedWriter {
    #[must_use]
    pub const fn expected_process_start(&self) -> [u8; 32] {
        self.binding.start
    }

    #[must_use]
    pub fn kill_binding(&self) -> ProviderCredentialBrokerKillBindingV1 {
        self.binding.clone()
    }
}

fn exact_32(value: &[u8]) -> Result<[u8; 32], ProviderCredentialEnrollmentHostError> {
    value
        .try_into()
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CredentialBrokerTransferAuthenticator, LaunchSecret};

    #[test]
    fn one_evidence_frame_cannot_mint_two_writer_witnesses() {
        let keys = LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys();
        let authenticator =
            CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let mut authority = ProviderCredentialBrokerTransferAuthority {
            seal: Arc::new(AuthoritySeal),
            transfer_seal: Arc::new(AuthoritySeal),
            protected_session_binding: [1; 32],
            authenticator,
            writer_evidence_available: true,
        };
        let mut record = [0_u8; 256];
        record[..32].copy_from_slice(&[1; 32]);
        record[32..64].copy_from_slice(&[2; 32]);
        record[64..96].copy_from_slice(&[3; 32]);
        let mut challenge = EVIDENCE_CHALLENGE.to_vec();
        challenge.extend_from_slice(&record[..96]);
        record[96..128].copy_from_slice(&authority.authenticate_daemon_transfer(&challenge));
        record[128..160].copy_from_slice(&[4; 32]);
        record[160..192].copy_from_slice(&[5; 32]);
        record[192..224].copy_from_slice(&[6; 32]);
        record[224..256].copy_from_slice(&[7; 32]);
        let mut response = EVIDENCE_RESPONSE.to_vec();
        response.extend_from_slice(&record);
        let proof = authority.authenticator.authenticate_transfer(&response);

        assert!(
            authority
                .verify_writer_evidence(&record, &proof, [6; 32], [1; 32], [2; 32])
                .is_ok()
        );
        assert!(
            authority
                .verify_writer_evidence(&record, &proof, [6; 32], [1; 32], [2; 32])
                .is_err()
        );
    }
}
