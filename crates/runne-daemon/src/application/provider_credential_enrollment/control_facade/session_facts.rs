#[cfg(any(
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    )
))]
use runne_api::{
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProviderCredentialEnrollmentHostError,
};
use sha2::{Digest, Sha256};

const SESSION_DOMAIN: &[u8] = b"gocode/provider-credential-enrollment/session/v1\0";
const DAEMON_DOMAIN: &[u8] = b"gocode/provider-credential-enrollment/daemon/v1\0";

type HttpAuthorityParts = (
    [u8; 16],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    u64,
    [u8; 32],
    u64,
    [u8; 32],
);

/// Exact non-secret V3 and native-release facts admitted before any begin.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ProtectedEnrollmentSessionFacts {
    pub(crate) launch_authority: [u8; 16],
    pub(crate) session: [u8; 16],
    pub(crate) daemon: [u8; 16],
    pub(crate) launch_generation: u64,
    pub(crate) installation: [u8; 32],
    pub(crate) release: [u8; 32],
    pub(crate) tauri_peer: [u8; 32],
    pub(crate) supervisor_generation: u64,
    pub(crate) runtime_authority: [u8; 16],
    pub(crate) database_generation: u64,
}

impl ProtectedEnrollmentSessionFacts {
    pub(crate) fn http_authority_parts(&self) -> HttpAuthorityParts {
        (
            self.session,
            self.installation,
            self.release,
            session_binding(self),
            self.supervisor_generation,
            self.tauri_peer,
            self.database_generation,
            daemon_binding(self),
        )
    }

    #[cfg(any(
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        )
    ))]
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

    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    pub(crate) fn from_verified_v2_status(
        owned: &ProtectedOwnedLaunchV2,
        installation: [u8; 32],
        release: [u8; 32],
        tauri_peer: [u8; 32],
        supervisor_generation: u64,
        runtime_authority: [u8; 16],
        database_generation: u64,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        if installation == [0; 32]
            || release == [0; 32]
            || tauri_peer == [0; 32]
            || supervisor_generation == 0
            || runtime_authority == [0; 16]
            || database_generation == 0
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(Self {
            launch_authority: *owned.launch_authority_id(),
            session: *owned.session_id(),
            daemon: *owned.daemon_instance_id(),
            launch_generation: owned.launch_generation(),
            installation,
            release,
            tauri_peer,
            supervisor_generation,
            runtime_authority,
            database_generation,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
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

    #[cfg(test)]
    pub(in crate::application::provider_credential_enrollment::control_facade) fn for_test_with_session(
        session: [u8; 16],
    ) -> Self {
        let mut facts = Self::for_test();
        facts.session = session;
        facts
    }
}

pub(crate) fn session_binding(facts: &ProtectedEnrollmentSessionFacts) -> [u8; 32] {
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

pub(crate) fn daemon_binding(facts: &ProtectedEnrollmentSessionFacts) -> [u8; 32] {
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
