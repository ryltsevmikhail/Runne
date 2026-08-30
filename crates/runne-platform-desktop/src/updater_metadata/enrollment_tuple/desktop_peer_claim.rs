use sha2::{Digest as _, Sha256};

use crate::ProtectedBundledRuntimeError;

/// Retained installed facts for one credential enrollment transition.
#[derive(Clone, Copy)]
pub struct EnrollmentTransitionFacts {
    /// Release tuple digest of the retained installed tuple.
    pub release_tuple_digest: [u8; 32],
    /// Qualification digest retained from the threshold-signed qualification.
    pub qualification_binding_digest: [u8; 32],
    /// Launch generation recorded at native confirmation time.
    pub supervisor_generation: u64,
}

use super::{ConfirmedInstalledNativeEnrollment, enrollment_live_daemon::ProtectedDaemonTupleEvidence};

impl ConfirmedInstalledNativeEnrollment {
    /// Derives a non-secret binding for the intent registry without exposing
    /// the protected session, release tuple, or process identity fields.
    #[must_use]
    pub fn intent_session_binding(&self) -> [u8; 32] {
        let evidence = &self.evidence;
        hash_intent(evidence)
    }

    /// Retained installed facts for one credential enrollment transition.
    ///
    /// Fails closed unless the retained qualification is still bound.
    #[must_use]
    pub fn enrollment_transition_facts(&self) -> Option<EnrollmentTransitionFacts> {
        Some(EnrollmentTransitionFacts {
            release_tuple_digest: self.evidence.release_tuple,
            qualification_binding_digest: self
                .admission
                .qualification
                .retained_qualification_binding_digest()?,
            supervisor_generation: self.evidence.generation,
        })
    }

    /// Mints one verified macOS writer launch from the retained admission.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the retained paths or writer identity are
    /// unavailable or the re-measured writer does not match the tuple.
    pub fn verified_macos_writer_launch(
        &self,
    ) -> Result<crate::VerifiedMacOsWriterLaunch, ProtectedBundledRuntimeError> {
        let paths = self
            .paths
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let executable = paths.writer_executable_path();
        self.admission
            .verified_macos_writer(executable)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
    }

    /// Revalidates the signed current desktop before deriving its peer claim.
    #[cfg(target_os = "macos")]
    pub fn current_desktop_peer_binding_digest(
        &self,
        supervisor_generation: std::num::NonZeroU64,
    ) -> Result<[u8; 32], ProtectedBundledRuntimeError> {
        let paths = self
            .paths
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let identity = self
            .admission
            .macos_desktop_code_identity
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let pid = std::num::NonZeroU32::new(std::process::id())
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let before = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?
            .digest();
        paths
            .confirm_current_macos_desktop(self.admission.desktop_sha256, identity)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let after = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?
            .digest();
        (before != [0; 32] && before == after)
            .then_some(())
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let euid = nix::unistd::geteuid().as_raw();
        Ok(desktop_peer_digest(
            self.evidence.release_tuple,
            self.admission.desktop_sha256,
            after,
            euid,
            self.evidence.launch_authority,
            self.evidence.desktop_host,
            supervisor_generation.get(),
        ))
    }

    /// Fails closed where the native macOS peer cannot be authenticated.
    #[cfg(not(target_os = "macos"))]
    pub fn current_desktop_peer_binding_digest(
        &self,
        _supervisor_generation: std::num::NonZeroU64,
    ) -> Result<[u8; 32], ProtectedBundledRuntimeError> {
        Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
    }
}

pub(super) fn desktop_peer_digest(
    release_tuple: [u8; 32],
    desktop_sha256: [u8; 32],
    process_start: [u8; 32],
    euid: u32,
    launch_authority: [u8; 16],
    desktop_host: [u8; 16],
    generation: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/provider-credential/desktop-peer-binding/v1\0");
    for value in [
        release_tuple.as_slice(),
        desktop_sha256.as_slice(),
        process_start.as_slice(),
        euid.to_be_bytes().as_slice(),
        launch_authority.as_slice(),
        desktop_host.as_slice(),
        generation.to_be_bytes().as_slice(),
    ] {
        hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(value);
    }
    hasher.finalize().into()
}

fn hash_intent(evidence: &ProtectedDaemonTupleEvidence) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/provider-credential/intent-session-binding/v1\0");
    for value in [
        evidence.release_tuple.as_slice(),
        evidence.launch_authority.as_slice(),
        evidence.session.as_slice(),
        evidence.daemon.as_slice(),
        evidence.process_start.as_slice(),
    ] {
        hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(value);
    }
    hasher.update(evidence.generation.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
#[path = "desktop_peer_claim/tests.rs"]
mod tests;
