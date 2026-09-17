/// Borrowed claims from an already authenticated V2 enrollment prepare.
///
/// This value has no public constructor and exposes neither the transport
/// proof nor a path to bypass the original MAC, owner, or sequence checks.
pub struct VerifiedProtectedCredentialEnrollmentPrepareV2<'a> {
    release_tuple_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
    desktop_peer_binding_digest: [u8; 32],
    desktop_supervisor_generation: u64,
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    _prepare: std::marker::PhantomData<&'a ProtectedCredentialEnrollmentPrepareV2>,
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
        Ok(VerifiedProtectedCredentialEnrollmentPrepareV2::from_prepare(self))
    }
}

impl VerifiedProtectedCredentialEnrollmentPrepareV2<'_> {
    const fn from_prepare(prepare: &ProtectedCredentialEnrollmentPrepareV2) -> Self {
        Self::from_claims(
            prepare.release_tuple_digest,
            prepare.qualification_binding_digest,
            prepare.desktop_peer_binding_digest,
            prepare.desktop_supervisor_generation,
            *prepare.owned_launch.launch_authority_id(),
            *prepare.owned_launch.desktop_host_instance_id(),
        )
    }

    pub(crate) const fn from_verified_status_claims(
        release_tuple_digest: [u8; 32],
        qualification_binding_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        desktop_supervisor_generation: u64,
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
    ) -> Self {
        Self::from_claims(
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
            launch_authority_id,
            desktop_host_instance_id,
        )
    }

    const fn from_claims(
        release_tuple_digest: [u8; 32],
        qualification_binding_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        desktop_supervisor_generation: u64,
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
    ) -> Self {
        Self {
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
            launch_authority_id,
            desktop_host_instance_id,
            _prepare: std::marker::PhantomData,
        }
    }

    #[must_use]
    pub const fn release_tuple_digest(&self) -> &[u8; 32] {
        &self.release_tuple_digest
    }

    #[must_use]
    pub const fn qualification_binding_digest(&self) -> &[u8; 32] {
        &self.qualification_binding_digest
    }

    #[must_use]
    pub const fn desktop_peer_binding_digest(&self) -> &[u8; 32] {
        &self.desktop_peer_binding_digest
    }

    #[must_use]
    pub const fn desktop_supervisor_generation(&self) -> u64 {
        self.desktop_supervisor_generation
    }

    #[must_use]
    pub const fn launch_authority_id(&self) -> &[u8; 16] {
        &self.launch_authority_id
    }

    #[must_use]
    pub const fn desktop_host_instance_id(&self) -> &[u8; 16] {
        &self.desktop_host_instance_id
    }
}

/// ```compile_fail
/// use runne_api::VerifiedProtectedCredentialEnrollmentPrepareV2;
///
/// let _ = VerifiedProtectedCredentialEnrollmentPrepareV2 {
///     release_tuple_digest: todo!(), qualification_binding_digest: todo!(),
///     desktop_peer_binding_digest: todo!(), desktop_supervisor_generation: todo!(),
///     launch_authority_id: todo!(), desktop_host_instance_id: todo!(), _prepare: todo!(),
/// };
/// ```
const _: () = ();
