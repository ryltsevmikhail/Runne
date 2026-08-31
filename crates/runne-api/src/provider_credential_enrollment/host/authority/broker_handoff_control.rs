use crate::ProtectedActivationKeys;

const BROKER_HANDOFF_WINDOW_MILLIS: u64 = 30_000;

/// One authenticated V3 control frame of the broker writer handoff.
///
/// Phases: the desktop offers one purpose (`PHASE_OFFER`), the daemon commits
/// with a nonce-echoing `PHASE_READY`, and after the authenticated kill
/// exchange the daemon proves completion with `PHASE_ACK`. Offer proofs use
/// the desktop transfer key; Ready and Ack proofs use the daemon transfer key.
pub struct ProviderCredentialBrokerHandoffFrame {
    phase: u8,
    purpose: u8,
    context: ProviderCredentialBrokerHandoffContext,
    issued_unix_millis: u64,
    expires_unix_millis: u64,
    nonce: [u8; 16],
    proof: [u8; 32],
}

impl ProviderCredentialBrokerHandoffFrame {
    pub const PHASE_OFFER: u8 = 1;
    pub const PHASE_READY: u8 = 2;
    pub const PHASE_ACK: u8 = 3;
    pub const PURPOSE_ENDPOINT: u8 = 1;
    pub const PURPOSE_EVIDENCE: u8 = 2;
    pub const PURPOSE_KILL: u8 = 3;

    /// Desktop offer that begins one exact handoff purpose on the channel.
    pub fn offer(
        context: ProviderCredentialBrokerHandoffContext,
        purpose: u8,
        issued_unix_millis: u64,
        expires_unix_millis: u64,
        nonce: [u8; 16],
        keys: &CredentialBrokerTransferAuthenticator,
    ) -> Result<Self, LaunchAuthorityError> {
        let mut frame = Self::new(
            Self::PHASE_OFFER,
            purpose,
            context,
            issued_unix_millis,
            expires_unix_millis,
            nonce,
        )?;
        frame.seal(keys);
        Ok(frame)
    }

    /// Daemon commitment echoing the exact offer nonce and binding.
    #[must_use]
    pub fn ready(&self, keys: &CredentialBrokerTransferAuthenticator) -> Self {
        self.echo(Self::PHASE_READY, keys)
    }

    /// Daemon proof that the authenticated kill exchange completed.
    #[must_use]
    pub fn acknowledgement(&self, keys: &CredentialBrokerTransferAuthenticator) -> Self {
        self.echo(Self::PHASE_ACK, keys)
    }

    /// Encodes one ordinary protected-channel frame including its length prefix.
    #[must_use]
    pub fn encode_frame(&self) -> Vec<u8> {
        let unsigned = self.unsigned();
        let total = u32::try_from(unsigned.len() + BROKER_HANDOFF_PROOF_BYTES).unwrap_or(0);
        let mut frame = Vec::with_capacity(4 + unsigned.len() + BROKER_HANDOFF_PROOF_BYTES);
        frame.extend_from_slice(&total.to_be_bytes());
        frame.extend_from_slice(&unsigned);
        frame.extend_from_slice(&self.proof);
        frame
    }

    /// Verifies one frame against the exact expected phase facts. A zero
    /// `expected_nonce` accepts any nonzero offer nonce; Ready and Ack callers
    /// must pass the exact offer nonce. A substituted echo never verifies.
    pub fn decode_and_verify(
        frame: &[u8],
        keys: &CredentialBrokerTransferAuthenticator,
        expected: &ProviderCredentialBrokerHandoffContext,
        expected_phase: u8,
        expected_purpose: u8,
        expected_nonce: [u8; 16],
        now_unix_millis: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        let total = 4 + BROKER_HANDOFF_UNSIGNED_BYTES + BROKER_HANDOFF_PROOF_BYTES;
        if frame.len() != total
            || u32::from_be_bytes(frame[..4].try_into().unwrap_or([0; 4])) as usize != total - 4
            || frame[4..12] != *BROKER_HANDOFF_MAGIC
            || frame[12] != expected_phase
            || frame[13] != expected_purpose
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let unsigned: [u8; BROKER_HANDOFF_UNSIGNED_BYTES] = frame
            [4..4 + BROKER_HANDOFF_UNSIGNED_BYTES]
            .try_into()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        let proof: [u8; BROKER_HANDOFF_PROOF_BYTES] = frame
            [4 + BROKER_HANDOFF_UNSIGNED_BYTES..]
            .try_into()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        let decoded = Self::from_unsigned(&unsigned, proof)?;
        if decoded.context != *expected
            || (expected_nonce == [0; 16] && decoded.nonce == [0; 16])
            || (expected_nonce != [0; 16] && decoded.nonce != expected_nonce)
            || now_unix_millis < decoded.issued_unix_millis
            || now_unix_millis > decoded.expires_unix_millis
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let verified = if expected_phase == Self::PHASE_OFFER {
            keys.verifies_desktop_transfer(&unsigned, &proof)
        } else {
            keys.verifies_transfer(&unsigned, &proof)
        };
        if !verified {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(decoded)
    }

    #[must_use]
    pub const fn purpose(&self) -> u8 {
        self.purpose
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    fn new(
        phase: u8,
        purpose: u8,
        context: ProviderCredentialBrokerHandoffContext,
        issued_unix_millis: u64,
        expires_unix_millis: u64,
        nonce: [u8; 16],
    ) -> Result<Self, LaunchAuthorityError> {
        if !matches!(
            purpose,
            Self::PURPOSE_ENDPOINT | Self::PURPOSE_EVIDENCE | Self::PURPOSE_KILL
        ) || nonce == [0; 16]
            || issued_unix_millis == 0
            || expires_unix_millis <= issued_unix_millis
            || expires_unix_millis - issued_unix_millis > BROKER_HANDOFF_WINDOW_MILLIS
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            phase,
            purpose,
            context,
            issued_unix_millis,
            expires_unix_millis,
            nonce,
            proof: [0; 32],
        })
    }

    fn echo(&self, phase: u8, keys: &CredentialBrokerTransferAuthenticator) -> Self {
        let mut echo = Self {
            phase,
            ..self.clone_unsigned()
        };
        echo.seal(keys);
        echo
    }

    const fn clone_unsigned(&self) -> Self {
        Self {
            phase: self.phase,
            purpose: self.purpose,
            context: ProviderCredentialBrokerHandoffContext {
                authority_id: self.context.authority_id,
                session_id: self.context.session_id,
                launch_generation: self.context.launch_generation,
                binding: self.context.binding,
            },
            issued_unix_millis: self.issued_unix_millis,
            expires_unix_millis: self.expires_unix_millis,
            nonce: self.nonce,
            proof: [0; 32],
        }
    }

    fn seal(&mut self, keys: &CredentialBrokerTransferAuthenticator) {
        let unsigned = self.unsigned();
        self.proof = if self.phase == Self::PHASE_OFFER {
            keys.authenticate_transfer(&unsigned)
        } else {
            keys.authenticate_daemon_transfer(&unsigned)
        };
    }

    fn unsigned(&self) -> [u8; BROKER_HANDOFF_UNSIGNED_BYTES] {
        let mut value = [0; BROKER_HANDOFF_UNSIGNED_BYTES];
        value[..8].copy_from_slice(BROKER_HANDOFF_MAGIC);
        value[8] = self.phase;
        value[9] = self.purpose;
        let mut index = 16;
        value[index..index + 16].copy_from_slice(&self.context.authority_id);
        index += 16;
        value[index..index + 16].copy_from_slice(&self.context.session_id);
        index += 16;
        value[index..index + 8].copy_from_slice(&self.context.launch_generation.to_be_bytes());
        index += 8;
        value[index..index + 8].copy_from_slice(&self.issued_unix_millis.to_be_bytes());
        index += 8;
        value[index..index + 8].copy_from_slice(&self.expires_unix_millis.to_be_bytes());
        index += 8;
        value[index..index + 16].copy_from_slice(&self.nonce);
        index += 16;
        value[index..index + 32].copy_from_slice(&self.context.binding);
        value
    }

    fn from_unsigned(
        unsigned: &[u8; BROKER_HANDOFF_UNSIGNED_BYTES],
        proof: [u8; BROKER_HANDOFF_PROOF_BYTES],
    ) -> Result<Self, LaunchAuthorityError> {
        if unsigned[10..16].iter().any(|byte| *byte != 0)
            || unsigned[120..128].iter().any(|byte| *byte != 0)
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let take16 =
            |start: usize| -> [u8; 16] { unsigned[start..start + 16].try_into().unwrap() };
        let take8 = |start: usize| -> u64 {
            u64::from_be_bytes(unsigned[start..start + 8].try_into().unwrap())
        };
        Ok(Self {
            phase: unsigned[8],
            purpose: unsigned[9],
            context: ProviderCredentialBrokerHandoffContext {
                authority_id: take16(16),
                session_id: take16(32),
                launch_generation: take8(48),
                binding: unsigned[88..120].try_into().unwrap(),
            },
            issued_unix_millis: take8(56),
            expires_unix_millis: take8(64),
            nonce: take16(72),
            proof,
        })
    }
}

impl fmt::Debug for ProviderCredentialBrokerHandoffFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCredentialBrokerHandoffFrame")
            .field("phase", &self.phase)
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

