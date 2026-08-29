const KILL_BINDING_WIRE_BYTES: usize = 192;
const KILL_RELINQUISHED_WIRE_BYTES: usize = KILL_BINDING_WIRE_BYTES + 64;

impl ProviderCredentialBrokerKillBindingV1 {
    #[must_use]
    pub fn to_exact_wire(&self) -> [u8; KILL_BINDING_WIRE_BYTES] {
        let mut wire = [0; KILL_BINDING_WIRE_BYTES];
        for (index, field) in [
            self.start,
            self.image,
            self.release,
            self.channel,
            self.key,
            self.writer_kill_public_key,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = index * 32;
            wire[offset..offset + 32].copy_from_slice(&field);
        }
        wire
    }
}

impl ProviderCredentialBrokerKillRelinquishedProof {
    #[must_use]
    pub fn to_exact_wire(&self) -> [u8; KILL_RELINQUISHED_WIRE_BYTES] {
        let mut wire = [0; KILL_RELINQUISHED_WIRE_BYTES];
        wire[..KILL_BINDING_WIRE_BYTES].copy_from_slice(&self.binding.to_exact_wire());
        wire[KILL_BINDING_WIRE_BYTES..].copy_from_slice(&self.signature);
        wire
    }
}

impl ProviderCredentialBrokerTransferAuthority {
    /// Decodes relinquishment only against this transfer's captured writer.
    pub fn accept_kill_relinquished_wire_for_captured(
        &self,
        wire: &[u8],
        captured: &ProviderCredentialBrokerCapturedWriter,
    ) -> Result<ProviderCredentialBrokerKillRelinquishedProof, ProviderCredentialEnrollmentHostError>
    {
        let wire: &[u8; KILL_RELINQUISHED_WIRE_BYTES] = wire
            .try_into()
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let proof = ProviderCredentialBrokerKillRelinquishedProof {
            binding: binding_from_exact_wire(&wire[..KILL_BINDING_WIRE_BYTES])?,
            signature: wire[KILL_BINDING_WIRE_BYTES..]
                .try_into()
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
        };
        self.verifies_kill_relinquished_for_captured(&proof, captured)
            .then_some(proof)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

fn binding_from_exact_wire(
    wire: &[u8],
) -> Result<ProviderCredentialBrokerKillBindingV1, ProviderCredentialEnrollmentHostError> {
    let wire: &[u8; KILL_BINDING_WIRE_BYTES] = wire
        .try_into()
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
    let field = |index: usize| {
        wire[index * 32..(index + 1) * 32]
            .try_into()
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    };
    let binding = ProviderCredentialBrokerKillBindingV1::new(
        field(0)?,
        field(1)?,
        field(2)?,
        field(3)?,
        field(4)?,
        field(5)?,
    );
    binding
        .is_complete()
        .then_some(binding)
        .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
}
