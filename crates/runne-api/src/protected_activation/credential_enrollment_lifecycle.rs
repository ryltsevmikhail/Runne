const ENROLLMENT_LIFECYCLE_MAGIC: &[u8; 8] = b"GCPCLIFE";
const ENROLLMENT_LIFECYCLE_DOMAIN: &[u8] =
    b"gocode/protected-credential-enrollment-lifecycle/v1";
const ENROLLMENT_LIFECYCLE_MAX_PAYLOAD: usize = 4_096;
/// Exact provider-owned offer/publication relay size, audited cross-crate.
pub const PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES: usize = 388;
const ENROLLMENT_LIFECYCLE_HEADER_BYTES: usize = 8 + 1 + 1 + 8 + 4;
const ENROLLMENT_LIFECYCLE_PROOF_BYTES: usize = 32;

const DESKTOP_DIRECTION: u8 = 1;
const DAEMON_DIRECTION: u8 = 2;
const BEGIN_KIND: u8 = 1;
const SNAPSHOT_KIND: u8 = 2;
const RELAY_KIND: u8 = 3;
const RELAY_ACK_KIND: u8 = 4;
const VERIFY_KIND: u8 = 5;

/// Authenticated, bounded lifecycle messages carried only by protected V3 control.
pub struct ProtectedCredentialEnrollmentLifecycleCodec {
    key: Zeroizing<[u8; 32]>,
}

impl ProtectedCredentialEnrollmentLifecycleCodec {
    /// Derives a role-separated lifecycle key from a protected activation.
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            key: Zeroizing::new(derive_key(
                keys.readiness_key(),
                ENROLLMENT_LIFECYCLE_DOMAIN,
            )),
        }
    }

    /// Encodes the native desktop's canonical enrollment begin command.
    pub fn encode_desktop_begin(
        &self,
        begin: &crate::BeginProviderCredentialEnrollment,
        sequence: u64,
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        let payload = serde_json::to_vec(begin).map_err(|_| LaunchAuthorityError::InvalidContract)?;
        self.encode(DESKTOP_DIRECTION, BEGIN_KIND, sequence, &payload)
    }

    /// Decodes exactly the next canonical enrollment begin command.
    pub fn decode_desktop_begin(
        &self,
        frame: &[u8],
        previous_sequence: u64,
    ) -> Result<crate::BeginProviderCredentialEnrollment, LaunchAuthorityError> {
        let payload = self.decode(
            frame,
            DESKTOP_DIRECTION,
            BEGIN_KIND,
            previous_sequence,
        )?;
        decode_canonical_json(payload)
    }

    /// Encodes the native desktop's canonical remote verification command.
    pub fn encode_desktop_verify(
        &self,
        verify: &crate::VerifyProviderCredential,
        sequence: u64,
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        let payload =
            serde_json::to_vec(verify).map_err(|_| LaunchAuthorityError::InvalidContract)?;
        self.encode(DESKTOP_DIRECTION, VERIFY_KIND, sequence, &payload)
    }

    /// Decodes exactly the next canonical remote verification command.
    pub fn decode_desktop_verify(
        &self,
        frame: &[u8],
        previous_sequence: u64,
    ) -> Result<crate::VerifyProviderCredential, LaunchAuthorityError> {
        let payload = self.decode(
            frame,
            DESKTOP_DIRECTION,
            VERIFY_KIND,
            previous_sequence,
        )?;
        decode_canonical_json(payload)
    }

    /// Encodes a safe daemon-owned enrollment snapshot.
    pub fn encode_daemon_snapshot(
        &self,
        snapshot: &crate::ProviderCredentialOperationSnapshotV2,
        sequence: u64,
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        let payload =
            serde_json::to_vec(snapshot).map_err(|_| LaunchAuthorityError::InvalidContract)?;
        self.encode(DAEMON_DIRECTION, SNAPSHOT_KIND, sequence, &payload)
    }

    /// Decodes exactly the next canonical safe daemon snapshot.
    pub fn decode_daemon_snapshot(
        &self,
        frame: &[u8],
        previous_sequence: u64,
    ) -> Result<crate::ProviderCredentialOperationSnapshotV2, LaunchAuthorityError> {
        let payload = self.decode(
            frame,
            DAEMON_DIRECTION,
            SNAPSHOT_KIND,
            previous_sequence,
        )?;
        decode_canonical_json(payload)
    }

    /// Encodes the fixed daemon-to-native secret relay bytes.
    pub fn encode_daemon_relay(
        &self,
        relay: &[u8],
        sequence: u64,
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        if relay.len() != PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.encode(DAEMON_DIRECTION, RELAY_KIND, sequence, relay)
    }

    /// Opens exactly the next daemon-to-native secret relay.
    pub fn decode_daemon_relay(
        &self,
        frame: &[u8],
        previous_sequence: u64,
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        let relay = self.decode(frame, DAEMON_DIRECTION, RELAY_KIND, previous_sequence)?;
        if relay.len() != PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(relay.to_owned())
    }

    /// Acknowledges the digest of the exact relay bytes consumed by native code.
    pub fn encode_desktop_relay_ack(
        &self,
        relay: &[u8],
        sequence: u64,
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        if relay.len() != PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let digest: [u8; 32] = Sha256::digest(relay).into();
        self.encode(DESKTOP_DIRECTION, RELAY_ACK_KIND, sequence, &digest)
    }

    /// Verifies the next acknowledgement against the exact expected relay.
    pub fn decode_desktop_relay_ack(
        &self,
        frame: &[u8],
        previous_sequence: u64,
        expected_relay: &[u8],
    ) -> Result<(), LaunchAuthorityError> {
        let payload = self.decode(
            frame,
            DESKTOP_DIRECTION,
            RELAY_ACK_KIND,
            previous_sequence,
        )?;
        if expected_relay.len() != PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let expected: [u8; 32] = Sha256::digest(expected_relay).into();
        if payload.len() != expected.len() || !bool::from(payload.ct_eq(&expected)) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(())
    }

    fn encode(
        &self,
        direction: u8,
        kind: u8,
        sequence: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        if payload.len() > ENROLLMENT_LIFECYCLE_MAX_PAYLOAD || sequence == 0 {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        let body_len = ENROLLMENT_LIFECYCLE_HEADER_BYTES + payload.len()
            + ENROLLMENT_LIFECYCLE_PROOF_BYTES;
        let mut frame = Vec::with_capacity(4 + body_len);
        frame.extend_from_slice(
            &u32::try_from(body_len)
                .map_err(|_| LaunchAuthorityError::InvalidContract)?
                .to_be_bytes(),
        );
        frame.extend_from_slice(ENROLLMENT_LIFECYCLE_MAGIC);
        frame.push(direction);
        frame.push(kind);
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(payload);
        let proof = authenticated_mac(&self.key, ENROLLMENT_LIFECYCLE_DOMAIN, &frame[4..]);
        frame.extend_from_slice(&proof);
        Ok(frame)
    }

    fn decode<'a>(
        &self,
        frame: &'a [u8],
        direction: u8,
        kind: u8,
        previous_sequence: u64,
    ) -> Result<&'a [u8], LaunchAuthorityError> {
        let minimum = 4 + ENROLLMENT_LIFECYCLE_HEADER_BYTES + ENROLLMENT_LIFECYCLE_PROOF_BYTES;
        if frame.len() < minimum {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let declared = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        let body = &frame[4..];
        if declared != body.len()
            || &body[..8] != ENROLLMENT_LIFECYCLE_MAGIC
            || body[8] != direction
            || body[9] != kind
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let sequence = u64::from_be_bytes(body[10..18].try_into().unwrap());
        let payload_len = u32::from_be_bytes(body[18..22].try_into().unwrap()) as usize;
        let expected_sequence = previous_sequence
            .checked_add(1)
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        if sequence != expected_sequence
            || payload_len > ENROLLMENT_LIFECYCLE_MAX_PAYLOAD
            || body.len() != ENROLLMENT_LIFECYCLE_HEADER_BYTES + payload_len + 32
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let payload_end = ENROLLMENT_LIFECYCLE_HEADER_BYTES + payload_len;
        let expected = authenticated_mac(
            &self.key,
            ENROLLMENT_LIFECYCLE_DOMAIN,
            &frame[4..4 + payload_end],
        );
        if !bool::from(body[payload_end..].ct_eq(&expected)) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(&body[ENROLLMENT_LIFECYCLE_HEADER_BYTES..payload_end])
    }
}

fn decode_canonical_json<T: serde::de::DeserializeOwned + serde::Serialize>(
    payload: &[u8],
) -> Result<T, LaunchAuthorityError> {
    let value = serde_json::from_slice(payload).map_err(|_| LaunchAuthorityError::InvalidContract)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| LaunchAuthorityError::InvalidContract)?;
    if canonical != payload {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    Ok(value)
}

#[cfg(test)]
#[path = "credential_enrollment_lifecycle_tests.rs"]
mod credential_enrollment_lifecycle_tests;
