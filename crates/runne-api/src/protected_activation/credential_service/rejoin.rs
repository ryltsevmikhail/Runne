use runne_domain::id::validate_uuid_v7_bytes;
use subtle::ConstantTimeEq as _;

use super::{
    CREDENTIAL_SERVICE_MAX_FRAME_BYTES, CredentialServiceRegistrationError,
    CredentialServiceSessionAuthenticator,
};

const MAGIC: &[u8; 8] = b"RNREJN01";
const VERSION: u16 = 1;
const BINDING_BYTES: usize = 144;
const MAC_BYTES: usize = 32;
const FRAME_BYTES: usize = 4 + MAGIC.len() + 2 + BINDING_BYTES + MAC_BYTES;
const MAC_DOMAIN: &[u8] = b"gocode/macos-credential-service/rejoin-required/v1\0";

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialServiceRejoinBinding {
    service_epoch: [u8; 16],
    protected_session_id: [u8; 16],
    daemon_authority_generation: u64,
    runtime_generation: u64,
    supervisor_generation: u64,
    installed_generation: u64,
    installation_owner: [u8; 32],
    release_binding: [u8; 32],
    join_attempt: u64,
    expires_at_unix_millis: u64,
}

impl CredentialServiceRejoinBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service_epoch: [u8; 16],
        protected_session_id: [u8; 16],
        daemon_authority_generation: u64,
        runtime_generation: u64,
        supervisor_generation: u64,
        installed_generation: u64,
        installation_owner: [u8; 32],
        release_binding: [u8; 32],
        join_attempt: u64,
        expires_at_unix_millis: u64,
    ) -> Result<Self, CredentialServiceRegistrationError> {
        if service_epoch == [0; 16]
            || validate_uuid_v7_bytes(&protected_session_id).is_err()
            || daemon_authority_generation == 0
            || runtime_generation == 0
            || supervisor_generation == 0
            || installed_generation == 0
            || installation_owner == [0; 32]
            || release_binding == [0; 32]
            || join_attempt == 0
            || expires_at_unix_millis == 0
        {
            return Err(CredentialServiceRegistrationError::InvalidBinding);
        }
        Ok(Self {
            service_epoch,
            protected_session_id,
            daemon_authority_generation,
            runtime_generation,
            supervisor_generation,
            installed_generation,
            installation_owner,
            release_binding,
            join_attempt,
            expires_at_unix_millis,
        })
    }

    pub const fn service_epoch(&self) -> [u8; 16] {
        self.service_epoch
    }
    pub const fn protected_session_id(&self) -> [u8; 16] {
        self.protected_session_id
    }
    pub const fn daemon_authority_generation(&self) -> u64 {
        self.daemon_authority_generation
    }
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }
    pub const fn supervisor_generation(&self) -> u64 {
        self.supervisor_generation
    }
    pub const fn installed_generation(&self) -> u64 {
        self.installed_generation
    }
    pub const fn installation_owner(&self) -> [u8; 32] {
        self.installation_owner
    }
    pub const fn release_binding(&self) -> [u8; 32] {
        self.release_binding
    }
    pub const fn join_attempt(&self) -> u64 {
        self.join_attempt
    }
    pub const fn expires_at_unix_millis(&self) -> u64 {
        self.expires_at_unix_millis
    }
}

pub struct CredentialServiceRejoinRequired {
    binding: CredentialServiceRejoinBinding,
    mac: [u8; MAC_BYTES],
}

impl CredentialServiceRejoinRequired {
    pub const fn binding(&self) -> &CredentialServiceRejoinBinding {
        &self.binding
    }
    pub fn into_control_frame(self) -> Vec<u8> {
        encode_frame(&self.binding, self.mac)
    }
}

impl CredentialServiceSessionAuthenticator {
    pub fn require_rejoin(
        &self,
        binding: CredentialServiceRejoinBinding,
    ) -> CredentialServiceRejoinRequired {
        let mac = self.runtime_mac(MAC_DOMAIN, &encode_binding(&binding));
        CredentialServiceRejoinRequired { binding, mac }
    }

    pub fn decode_and_verify_rejoin(
        &self,
        frame: &[u8],
        now_unix_millis: u64,
    ) -> Result<CredentialServiceRejoinRequired, CredentialServiceRegistrationError> {
        let required = decode_frame(frame)?;
        if required.binding.expires_at_unix_millis <= now_unix_millis {
            return Err(CredentialServiceRegistrationError::Expired);
        }
        let expected = self.runtime_mac(MAC_DOMAIN, &encode_binding(&required.binding));
        bool::from(expected.ct_eq(&required.mac))
            .then_some(required)
            .ok_or(CredentialServiceRegistrationError::AuthenticationFailed)
    }
}

fn encode_frame(binding: &CredentialServiceRejoinBinding, mac: [u8; MAC_BYTES]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_BYTES);
    let payload = u32::try_from(FRAME_BYTES - 4).expect("fixed rejoin frame fits u32");
    frame.extend_from_slice(&payload.to_be_bytes());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&VERSION.to_be_bytes());
    frame.extend(encode_binding(binding));
    frame.extend_from_slice(&mac);
    frame
}

fn decode_frame(
    frame: &[u8],
) -> Result<CredentialServiceRejoinRequired, CredentialServiceRegistrationError> {
    if frame.len() != FRAME_BYTES || frame.len() > CREDENTIAL_SERVICE_MAX_FRAME_BYTES + 4 {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    let mut prefix_index = 0;
    let payload = u32::from_be_bytes(take(frame, &mut prefix_index)?);
    if usize::try_from(payload).ok() != Some(frame.len() - 4)
        || frame.get(4..12) != Some(MAGIC)
        || frame.get(12..14) != Some(&VERSION.to_be_bytes())
    {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    let mut index = 14;
    let binding = CredentialServiceRejoinBinding::new(
        take(frame, &mut index)?,
        take(frame, &mut index)?,
        take_u64(frame, &mut index)?,
        take_u64(frame, &mut index)?,
        take_u64(frame, &mut index)?,
        take_u64(frame, &mut index)?,
        take(frame, &mut index)?,
        take(frame, &mut index)?,
        take_u64(frame, &mut index)?,
        take_u64(frame, &mut index)?,
    )?;
    let mac = take(frame, &mut index)?;
    (index == frame.len())
        .then_some(CredentialServiceRejoinRequired { binding, mac })
        .ok_or(CredentialServiceRegistrationError::InvalidFrame)
}

fn encode_binding(value: &CredentialServiceRejoinBinding) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BINDING_BYTES);
    bytes.extend_from_slice(&value.service_epoch);
    bytes.extend_from_slice(&value.protected_session_id);
    for value in [
        value.daemon_authority_generation,
        value.runtime_generation,
        value.supervisor_generation,
        value.installed_generation,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&value.installation_owner);
    bytes.extend_from_slice(&value.release_binding);
    bytes.extend_from_slice(&value.join_attempt.to_be_bytes());
    bytes.extend_from_slice(&value.expires_at_unix_millis.to_be_bytes());
    bytes
}

fn take_u64(bytes: &[u8], index: &mut usize) -> Result<u64, CredentialServiceRegistrationError> {
    Ok(u64::from_be_bytes(take(bytes, index)?))
}

fn take<const N: usize>(
    bytes: &[u8],
    index: &mut usize,
) -> Result<[u8; N], CredentialServiceRegistrationError> {
    let end = index
        .checked_add(N)
        .ok_or(CredentialServiceRegistrationError::InvalidFrame)?;
    let value = bytes
        .get(*index..end)
        .ok_or(CredentialServiceRegistrationError::InvalidFrame)?;
    *index = end;
    value
        .try_into()
        .map_err(|_| CredentialServiceRegistrationError::InvalidFrame)
}

impl core::fmt::Debug for CredentialServiceRejoinRequired {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CredentialServiceRejoinRequired(<authenticated>)")
    }
}

impl core::fmt::Debug for CredentialServiceRejoinBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialServiceRejoinBinding")
            .field(
                "daemon_authority_generation",
                &self.daemon_authority_generation,
            )
            .field("runtime_generation", &self.runtime_generation)
            .field("supervisor_generation", &self.supervisor_generation)
            .field("installed_generation", &self.installed_generation)
            .field("join_attempt", &self.join_attempt)
            .field("expires_at_unix_millis", &self.expires_at_unix_millis)
            .finish_non_exhaustive()
    }
}
