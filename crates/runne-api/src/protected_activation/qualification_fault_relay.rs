const QUALIFICATION_FAULT_RELAY_DOMAIN: &[u8] =
    b"gocode/native-qualification-fault-relay/v1";
const MAX_QUALIFICATION_FAULT_TICKET_BYTES: u32 = 4_096;

/// Exact authenticated direction for a qualification-only relay frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationFaultRelayDirectionV1 {
    DesktopToRuntime,
    RuntimeToWriter,
    RuntimeToService,
}

impl QualificationFaultRelayDirectionV1 {
    #[must_use]
    pub const fn wire_tag(self) -> u8 {
        match self {
            Self::DesktopToRuntime => 1,
            Self::RuntimeToWriter => 2,
            Self::RuntimeToService => 3,
        }
    }

    #[must_use]
    pub const fn from_wire_tag(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::DesktopToRuntime),
            2 => Some(Self::RuntimeToWriter),
            3 => Some(Self::RuntimeToService),
            _ => None,
        }
    }
}

/// Non-secret exact context authenticated by one relay frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationFaultRelayBindingV1 {
    protected_session_id: [u8; 16],
    release_tuple_v3_sha256: [u8; 32],
    launch_generation: u64,
    direction: QualificationFaultRelayDirectionV1,
    sequence: u64,
}

impl QualificationFaultRelayBindingV1 {
    /// Creates one exact relay binding.
    pub fn new(
        protected_session_id: [u8; 16],
        release_tuple_v3_sha256: [u8; 32],
        launch_generation: u64,
        direction: QualificationFaultRelayDirectionV1,
        sequence: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&protected_session_id).is_err()
            || release_tuple_v3_sha256 == [0; 32]
            || launch_generation == 0
            || sequence == 0
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            protected_session_id,
            release_tuple_v3_sha256,
            launch_generation,
            direction,
            sequence,
        })
    }

    #[must_use]
    pub const fn protected_session_id(&self) -> [u8; 16] {
        self.protected_session_id
    }

    #[must_use]
    pub const fn release_tuple_v3_sha256(&self) -> [u8; 32] {
        self.release_tuple_v3_sha256
    }

    #[must_use]
    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }

    #[must_use]
    pub const fn direction(&self) -> QualificationFaultRelayDirectionV1 {
        self.direction
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Digest-only ticket facts accepted by the purpose-specific relay MAC.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct QualificationFaultRelayTicketBindingV1 {
    presence_tag: u8,
    byte_length: u32,
    sha256: [u8; 32],
}

impl QualificationFaultRelayTicketBindingV1 {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            presence_tag: 0,
            byte_length: 0,
            sha256: [0; 32],
        }
    }

    /// Binds one non-empty bounded canonical ticket digest.
    pub fn present(byte_length: u32, sha256: [u8; 32]) -> Result<Self, LaunchAuthorityError> {
        if byte_length == 0
            || byte_length > MAX_QUALIFICATION_FAULT_TICKET_BYTES
            || sha256 == [0; 32]
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            presence_tag: 1,
            byte_length,
            sha256,
        })
    }
}

/// Purpose-specific MAC authority derived from one protected activation.
pub struct QualificationFaultRelayAuthenticator {
    key: Zeroizing<[u8; 32]>,
}

impl QualificationFaultRelayAuthenticator {
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            key: Zeroizing::new(derive_key(
                keys.readiness_key(),
                QUALIFICATION_FAULT_RELAY_DOMAIN,
            )),
        }
    }

    /// Authenticates only the closed qualification relay contract.
    #[must_use]
    pub fn authenticate(
        &self,
        binding: &QualificationFaultRelayBindingV1,
        ticket: &QualificationFaultRelayTicketBindingV1,
    ) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(102);
        bytes.extend_from_slice(&binding.protected_session_id);
        bytes.extend_from_slice(&binding.release_tuple_v3_sha256);
        bytes.extend_from_slice(&binding.launch_generation.to_be_bytes());
        bytes.push(binding.direction.wire_tag());
        bytes.extend_from_slice(&binding.sequence.to_be_bytes());
        bytes.push(ticket.presence_tag);
        bytes.extend_from_slice(&ticket.byte_length.to_be_bytes());
        bytes.extend_from_slice(&ticket.sha256);
        authenticated_mac(&self.key, QUALIFICATION_FAULT_RELAY_DOMAIN, &bytes)
    }

    #[must_use]
    pub fn verifies(
        &self,
        binding: &QualificationFaultRelayBindingV1,
        ticket: &QualificationFaultRelayTicketBindingV1,
        proof: &[u8; 32],
    ) -> bool {
        bool::from(self.authenticate(binding, ticket).ct_eq(proof))
    }
}

impl fmt::Debug for QualificationFaultRelayAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QualificationFaultRelayAuthenticator(<redacted>)")
    }
}

#[cfg(test)]
mod qualification_fault_relay_authenticator_tests {
    use super::*;

    fn uuid(byte: u8) -> [u8; 16] {
        [0x71, byte, byte, byte, byte, byte, 0x71, byte, 0x81, byte, byte, byte, byte, byte, byte, byte]
    }

    #[test]
    fn relay_authentication_is_domain_and_context_bound() {
        let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
        let auth = QualificationFaultRelayAuthenticator::from_protected_activation(&keys);
        let binding = QualificationFaultRelayBindingV1::new(
            uuid(1), [2; 32], 3, QualificationFaultRelayDirectionV1::DesktopToRuntime, 4,
        ).unwrap();
        let ticket = QualificationFaultRelayTicketBindingV1::present(12, [5; 32]).unwrap();
        let proof = auth.authenticate(&binding, &ticket);
        assert!(auth.verifies(&binding, &ticket, &proof));
        assert!(!auth.verifies(&binding, &QualificationFaultRelayTicketBindingV1::none(), &proof));
        assert!(!CredentialBrokerTransferAuthenticator::from_protected_activation(&keys)
            .verifies_transfer(b"qualification", &proof));
    }
}
