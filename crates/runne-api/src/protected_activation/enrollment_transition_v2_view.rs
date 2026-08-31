/// Borrowed claims from an already authenticated V2 enrollment prepare.
///
/// This value has no public constructor and exposes neither the transport
/// proof nor a path to bypass the original MAC, owner, or sequence checks.
pub struct VerifiedProtectedCredentialEnrollmentPrepareV2<'a> {
    prepare: &'a ProtectedCredentialEnrollmentPrepareV2,
}

impl ProtectedCredentialEnrollmentPrepareV2 {
    /// Verifies the exact V2 prepare before minting its borrowed claims view.
    pub fn verify_exact_view<'a>(
        &'a self,
        expected: &ProtectedOwnedLaunchV2,
        last_sequence: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<VerifiedProtectedCredentialEnrollmentPrepareV2<'a>, LaunchAuthorityError> {
        self.verify_exact(expected, last_sequence, keys)?;
        Ok(VerifiedProtectedCredentialEnrollmentPrepareV2 { prepare: self })
    }
}

impl VerifiedProtectedCredentialEnrollmentPrepareV2<'_> {
    #[must_use]
    pub const fn release_tuple_digest(&self) -> &[u8; 32] {
        &self.prepare.release_tuple_digest
    }

    #[must_use]
    pub const fn qualification_binding_digest(&self) -> &[u8; 32] {
        &self.prepare.qualification_binding_digest
    }

    #[must_use]
    pub const fn desktop_peer_binding_digest(&self) -> &[u8; 32] {
        &self.prepare.desktop_peer_binding_digest
    }

    #[must_use]
    pub const fn desktop_supervisor_generation(&self) -> u64 {
        self.prepare.desktop_supervisor_generation
    }

    #[must_use]
    pub const fn launch_authority_id(&self) -> &[u8; 16] {
        self.prepare.owned_launch.launch_authority_id()
    }

    #[must_use]
    pub const fn desktop_host_instance_id(&self) -> &[u8; 16] {
        self.prepare.owned_launch.desktop_host_instance_id()
    }
}

/// ```compile_fail
/// use runne_api::VerifiedProtectedCredentialEnrollmentPrepareV2;
///
/// let _ = VerifiedProtectedCredentialEnrollmentPrepareV2 { prepare: todo!() };
/// ```
const _: () = ();
