use super::{
    DaemonLaunchProtocolExpectation, DaemonLaunchRequest, ProtectedActivationChannel,
    VerifiedDaemonEnrollmentLaunchAuthority,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::protected_activation::installation_anchor::VerifiedNativeEnrollmentInstallation;
use runne_api::{
    ActivationDispositionV1, LaunchAuthorityError, LaunchAuthorityValidationV1,
    ProtectedActivationKeys, ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentPreludeV2, ProtectedCredentialEnrollmentPrepareV2,
    ProtectedLaunchRequestV2, ProtectedOwnedLaunchV2,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use runne_platform_desktop::VerifiedDaemonNativeEnrollmentPrepare;

/// Private witness minted only after all V2, native, and V3 exact checks pass.
pub(super) struct VerifiedV2EnrollmentEvidence {
    provider: runne_api::ProviderActivationBindingV1,
    binding: runne_api::ProtectedCredentialEnrollmentLaunchBindingV1,
    prelude: runne_api::DaemonEnrollmentLaunchPreludeV1,
}

impl VerifiedV2EnrollmentEvidence {
    fn mint(
        provider: runne_api::ProviderActivationBindingV1,
        binding: runne_api::ProtectedCredentialEnrollmentLaunchBindingV1,
        prelude: runne_api::DaemonEnrollmentLaunchPreludeV1,
    ) -> Self {
        Self {
            provider,
            binding,
            prelude,
        }
    }

    pub(super) fn into_authority_parts(
        self,
    ) -> (
        runne_api::ProviderActivationBindingV1,
        runne_api::ProtectedCredentialEnrollmentLaunchBindingV1,
        runne_api::DaemonEnrollmentLaunchPreludeV1,
    ) {
        (self.provider, self.binding, self.prelude)
    }
}

/// Daemon-private, move-only V3 transition prepared from exact V2 evidence.
pub(crate) struct PreparedDaemonEnrollmentTransitionV3 {
    request: DaemonLaunchRequest,
    keys: ProtectedActivationKeys,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    installed_facts: Option<runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts>,
}

impl PreparedDaemonEnrollmentTransitionV3 {
    pub(crate) const fn keys(&self) -> &ProtectedActivationKeys {
        &self.keys
    }

    pub(crate) fn enrollment(&self) -> Option<&ProtectedCredentialEnrollmentLaunchRequestV3> {
        match &self.request {
            DaemonLaunchRequest::V3(request) => Some(request),
            _ => None,
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn take_installed_facts(
        &mut self,
    ) -> Option<runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts> {
        self.installed_facts.take()
    }
}

pub(crate) struct V2TransitionInput<'a> {
    prepare: &'a ProtectedCredentialEnrollmentPrepareV2,
    signed_prelude: &'a ProtectedCredentialEnrollmentPreludeV2,
    expected_owned: &'a ProtectedOwnedLaunchV2,
    original_request: &'a ProtectedLaunchRequestV2,
    last_sequence: u64,
    keys: &'a ProtectedActivationKeys,
    now_unix_millis: u64,
    request_validation_now_millis: u64,
    installation: [u8; 32],
}

impl<'a> V2TransitionInput<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn new(
        prepare: &'a ProtectedCredentialEnrollmentPrepareV2,
        signed_prelude: &'a ProtectedCredentialEnrollmentPreludeV2,
        expected_owned: &'a ProtectedOwnedLaunchV2,
        original_request: &'a ProtectedLaunchRequestV2,
        last_sequence: u64,
        keys: &'a ProtectedActivationKeys,
        now_unix_millis: u64,
        request_validation_now_millis: u64,
        installation: [u8; 32],
    ) -> Self {
        Self {
            prepare,
            signed_prelude,
            expected_owned,
            original_request,
            last_sequence,
            keys,
            now_unix_millis,
            request_validation_now_millis,
            installation,
        }
    }
}

/// Revalidates exactly one native V2 peer before accepting its V3 launch.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn admit_v2_to_v3_transition(
    context: &V2TransitionInput<'_>,
    installation: &VerifiedNativeEnrollmentInstallation,
    native: VerifiedDaemonNativeEnrollmentPrepare,
    channel: &ProtectedActivationChannel,
    request: ProtectedCredentialEnrollmentLaunchRequestV3,
) -> Result<PreparedDaemonEnrollmentTransitionV3, LaunchAuthorityError> {
    let input = V2TransitionInput::new(
        context.prepare,
        context.signed_prelude,
        context.expected_owned,
        context.original_request,
        context.last_sequence,
        context.keys,
        context.now_unix_millis,
        context.request_validation_now_millis,
        *installation.installation_identity_digest(),
    );
    let installed = std::cell::RefCell::new(None);
    let mut prepared = transition_with(
        &input,
        request,
        |stream, claims| {
            *installed.borrow_mut() =
                native.revalidate_and_measure_current_peer_for_claims(stream, claims);
            installed.borrow().is_some()
        },
        channel,
    )?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        prepared.installed_facts = installed.into_inner();
    }
    Ok(prepared)
}

pub(super) fn transition_with<F>(
    context: &V2TransitionInput<'_>,
    request: ProtectedCredentialEnrollmentLaunchRequestV3,
    native_revalidate: F,
    channel: &ProtectedActivationChannel,
) -> Result<PreparedDaemonEnrollmentTransitionV3, LaunchAuthorityError>
where
    F: FnOnce(
        &std::os::unix::net::UnixStream,
        &runne_api::VerifiedProtectedCredentialEnrollmentPrepareV2<'_>,
    ) -> bool,
{
    let claims = context.prepare.verify_exact_view(
        context.expected_owned,
        context.last_sequence,
        context.keys,
    )?;
    context.signed_prelude.verify_exact_at(
        context.prepare,
        context.expected_owned,
        context.last_sequence,
        context.now_unix_millis,
        context.keys,
    )?;
    let prelude = context.signed_prelude.prelude();
    let binding = request.enrollment_binding();
    if !original_matches_owned(context)
        || !v3_matches_original(&request, context)
        || !native_revalidate(channel.unix_stream(), &claims)
        || prelude.installation_identity_digest() != &context.installation
        || prelude.desktop_peer_binding_digest() != context.prepare.desktop_peer_binding_digest()
        || prelude.supervisor_generation() != context.prepare.desktop_supervisor_generation()
        || binding.installation_identity_digest() != &context.installation
        || binding.release_tuple_digest() != context.prepare.release_tuple_digest()
        || binding.qualification_binding_digest() != context.prepare.qualification_binding_digest()
        || binding.desktop_peer_binding_digest() != context.prepare.desktop_peer_binding_digest()
        || binding.desktop_supervisor_generation()
            != context.prepare.desktop_supervisor_generation()
    {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    let authority =
        VerifiedDaemonEnrollmentLaunchAuthority::from_verified(VerifiedV2EnrollmentEvidence::mint(
            context.expected_owned.provider_binding().clone(),
            binding.clone(),
            prelude.clone(),
        ));
    let mut request = DaemonLaunchRequest::V3(request);
    request.validate_for_protocol(
        context.request_validation_now_millis,
        &LaunchAuthorityValidationV1 {
            principal_id: context.original_request.principal_id(),
            profile: context.original_request.profile(),
            executable: context.original_request.executable(),
        },
        DaemonLaunchProtocolExpectation::enrollment(authority),
    )?;
    let keys = request.derive_keys_and_forget();
    Ok(PreparedDaemonEnrollmentTransitionV3 { request, keys })
}

fn v3_matches_original(
    request: &ProtectedCredentialEnrollmentLaunchRequestV3,
    context: &V2TransitionInput<'_>,
) -> bool {
    request.launch_authority_id() == context.original_request.launch_authority_id()
        && request.desktop_host_instance_id() == context.original_request.desktop_host_instance_id()
        && request.principal_id() == context.original_request.principal_id()
        && request.profile() == context.original_request.profile()
        && request.executable() == context.original_request.executable()
        && request.runtime_root() == context.original_request.runtime_root()
        && request.provider_binding() == context.original_request.provider_binding()
        && request.provider_binding() == context.expected_owned.provider_binding()
        && matches!(
            request.activation_disposition(),
            ActivationDispositionV1::Existing(stable)
                if stable.as_ref() == context.expected_owned.compatibility_owned_launch().stable()
        )
}

fn original_matches_owned(context: &V2TransitionInput<'_>) -> bool {
    let original = context.original_request;
    let owned = context.expected_owned;
    original.launch_authority_id() == *owned.launch_authority_id()
        && original.desktop_host_instance_id() == *owned.desktop_host_instance_id()
        && original.executable() == owned.compatibility_owned_launch().executable()
        && original.profile() == owned.compatibility_owned_launch().profile()
        && original.provider_binding() == owned.provider_binding()
}

#[cfg(test)]
#[path = "enrollment_transition_v2_v3_tests.rs"]
mod tests;
