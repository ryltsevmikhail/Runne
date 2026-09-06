const QUALIFICATION_RUN_CONTEXT_RELAY_DOMAIN: &[u8] =
    b"gocode/native-qualification-run-context-relay/v1";
const MAX_QUALIFICATION_RUN_CONTEXT_BYTES: u32 = 2_048;

/// Exact authenticated direction for a runner-context relay frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationRunContextRelayDirectionV1 {
    DesktopToRuntime,
}

impl QualificationRunContextRelayDirectionV1 {
    #[must_use]
    pub const fn wire_tag(self) -> u8 {
        match self {
            Self::DesktopToRuntime => 1,
        }
    }

    #[must_use]
    pub const fn from_wire_tag(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::DesktopToRuntime),
            _ => None,
        }
    }
}

/// Non-secret exact context authenticated by one runner-context relay frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationRunContextRelayBindingV1 {
    protected_session_id: [u8; 16],
    release_tuple_v3_sha256: [u8; 32],
    launch_generation: u64,
    direction: QualificationRunContextRelayDirectionV1,
    sequence: u64,
}

impl QualificationRunContextRelayBindingV1 {
    /// Creates one exact Desktop-to-runtime runner-context relay binding.
    pub fn new(
        protected_session_id: [u8; 16],
        release_tuple_v3_sha256: [u8; 32],
        launch_generation: u64,
        direction: QualificationRunContextRelayDirectionV1,
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
    pub const fn direction(&self) -> QualificationRunContextRelayDirectionV1 {
        self.direction
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Digest-only runner-context facts accepted by the purpose-specific relay MAC.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct QualificationRunContextRelayContentBindingV1 {
    byte_length: u32,
    sha256: [u8; 32],
}

impl QualificationRunContextRelayContentBindingV1 {
    /// Binds one non-empty bounded canonical signed runner context.
    pub fn new(byte_length: u32, sha256: [u8; 32]) -> Result<Self, LaunchAuthorityError> {
        if byte_length == 0
            || byte_length > MAX_QUALIFICATION_RUN_CONTEXT_BYTES
            || sha256 == [0; 32]
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            byte_length,
            sha256,
        })
    }
}

/// Purpose-specific runner-context MAC authority derived from one activation.
pub struct QualificationRunContextRelayAuthenticator {
    key: Zeroizing<[u8; 32]>,
}

impl QualificationRunContextRelayAuthenticator {
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            key: Zeroizing::new(derive_key(
                keys.readiness_key(),
                QUALIFICATION_RUN_CONTEXT_RELAY_DOMAIN,
            )),
        }
    }

    /// Authenticates only the closed runner-context relay contract.
    #[must_use]
    pub fn authenticate(
        &self,
        binding: &QualificationRunContextRelayBindingV1,
        content: &QualificationRunContextRelayContentBindingV1,
    ) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(101);
        bytes.extend_from_slice(&binding.protected_session_id);
        bytes.extend_from_slice(&binding.release_tuple_v3_sha256);
        bytes.extend_from_slice(&binding.launch_generation.to_be_bytes());
        bytes.push(binding.direction.wire_tag());
        bytes.extend_from_slice(&binding.sequence.to_be_bytes());
        bytes.extend_from_slice(&content.byte_length.to_be_bytes());
        bytes.extend_from_slice(&content.sha256);
        authenticated_mac(&self.key, QUALIFICATION_RUN_CONTEXT_RELAY_DOMAIN, &bytes)
    }

    #[must_use]
    pub fn verifies(
        &self,
        binding: &QualificationRunContextRelayBindingV1,
        content: &QualificationRunContextRelayContentBindingV1,
        proof: &[u8; 32],
    ) -> bool {
        bool::from(self.authenticate(binding, content).ct_eq(proof))
    }
}

impl fmt::Debug for QualificationRunContextRelayAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QualificationRunContextRelayAuthenticator(<redacted>)")
    }
}

#[cfg(test)]
mod qualification_run_context_relay_authenticator_tests {
    use super::*;

    const fn uuid(byte: u8) -> [u8; 16] {
        [
            0x71, byte, byte, byte, byte, byte, 0x71, byte, 0x81, byte, byte, byte, byte, byte,
            byte, byte,
        ]
    }

    #[test]
    fn context_relay_has_a_distinct_domain_and_closed_binding() {
        let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
        let binding = QualificationRunContextRelayBindingV1::new(
            uuid(1),
            [2; 32],
            3,
            QualificationRunContextRelayDirectionV1::DesktopToRuntime,
            4,
        )
        .unwrap();
        let content = QualificationRunContextRelayContentBindingV1::new(12, [5; 32]).unwrap();
        let proof = QualificationRunContextRelayAuthenticator::from_protected_activation(&keys)
            .authenticate(&binding, &content);
        let fault_binding = QualificationFaultRelayBindingV1::new(
            uuid(1),
            [2; 32],
            3,
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            4,
        )
        .unwrap();
        let fault_content = QualificationFaultRelayTicketBindingV1::present(12, [5; 32]).unwrap();
        assert_ne!(
            proof,
            QualificationFaultRelayAuthenticator::from_protected_activation(&keys)
                .authenticate(&fault_binding, &fault_content)
        );
        assert!(QualificationRunContextRelayBindingV1::new(
            uuid(1),
            [2; 32],
            0,
            QualificationRunContextRelayDirectionV1::DesktopToRuntime,
            4,
        )
        .is_err());
        assert!(QualificationRunContextRelayContentBindingV1::new(0, [5; 32]).is_err());
    }
}
