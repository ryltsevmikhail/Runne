use runne_api::{
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProviderCredentialEnrollmentHostError,
};
use sha2::{Digest, Sha256};

const SESSION_DOMAIN: &[u8] = b"gocode/provider-credential-enrollment/session/v1\0";
const DAEMON_DOMAIN: &[u8] = b"gocode/provider-credential-enrollment/daemon/v1\0";

/// Exact non-secret V3 and native-release facts admitted before any begin.
pub(crate) struct ProtectedEnrollmentSessionFacts {
    pub(super) launch_authority: [u8; 16],
    pub(super) session: [u8; 16],
    pub(super) daemon: [u8; 16],
    pub(super) launch_generation: u64,
    pub(super) installation: [u8; 32],
    pub(super) release: [u8; 32],
    pub(super) tauri_peer: [u8; 32],
    pub(super) supervisor_generation: u64,
    pub(super) runtime_authority: [u8; 16],
    pub(super) database_generation: u64,
}

impl ProtectedEnrollmentSessionFacts {
    pub(crate) fn from_owned(
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        runtime_authority: [u8; 16],
        database_generation: u64,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        if runtime_authority == [0; 16] || database_generation == 0 {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let enrollment = owned.enrollment_binding();
        Ok(Self {
            launch_authority: *owned.launch_authority_id(),
            session: *owned.session_id(),
            daemon: *owned.daemon_instance_id(),
            launch_generation: owned.launch_generation(),
            installation: *enrollment.installation_identity_digest(),
            release: *enrollment.release_tuple_digest(),
            tauri_peer: *enrollment.desktop_peer_binding_digest(),
            supervisor_generation: enrollment.desktop_supervisor_generation(),
            runtime_authority,
            database_generation,
        })
    }

    #[cfg(test)]
    pub(in crate::application::provider_credential_enrollment::control_facade) fn for_test() -> Self
    {
        Self {
            launch_authority: id(1),
            session: id(2),
            daemon: id(3),
            launch_generation: 4,
            installation: [5; 32],
            release: [6; 32],
            tauri_peer: [7; 32],
            supervisor_generation: 8,
            runtime_authority: id(9),
            database_generation: 10,
        }
    }
}

pub(super) fn session_binding(facts: &ProtectedEnrollmentSessionFacts) -> [u8; 32] {
    digest(
        SESSION_DOMAIN,
        &[
            &facts.launch_authority,
            &facts.session,
            &facts.daemon,
            &facts.launch_generation.to_be_bytes(),
        ],
    )
}

pub(super) fn daemon_binding(facts: &ProtectedEnrollmentSessionFacts) -> [u8; 32] {
    digest(
        DAEMON_DOMAIN,
        &[
            &facts.daemon,
            &facts.runtime_authority,
            &facts.database_generation.to_be_bytes(),
        ],
    )
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70;
    value[8] = 0x80;
    value
}
