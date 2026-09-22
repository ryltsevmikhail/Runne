//! The daemon's authenticated target must also match the native host.
use super::{EnrollmentTransitionClaims, ProtectedBundledRuntimeError, launch_error};
use runne_api::{
    CredentialBrokerTransferCommitment, DaemonEnrollmentLaunchPreludeV1, LaunchAuthorityError,
    ProtectedCredentialEnrollmentLaunchBindingV1,
};

fn accepts(platform: u64, architecture: u64) -> bool {
    match (platform, architecture) {
        (1, 1) => cfg!(all(target_os = "macos", target_arch = "aarch64")),
        (2, 2) => cfg!(all(target_os = "linux", target_arch = "aarch64")),
        (2, 3) => cfg!(all(target_os = "linux", target_arch = "x86_64")),
        _ => false,
    }
}

pub(super) fn binding(
    claims: &EnrollmentTransitionClaims,
    prelude: &DaemonEnrollmentLaunchPreludeV1,
    commitment: CredentialBrokerTransferCommitment,
) -> Result<ProtectedCredentialEnrollmentLaunchBindingV1, ProtectedBundledRuntimeError> {
    if !accepts(prelude.platform(), prelude.architecture()) {
        return Err(launch_error(
            LaunchAuthorityError::UnsupportedPlatformBackend,
        ));
    }
    let constructor = match (prelude.platform(), prelude.architecture()) {
        (1, 1) => ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon,
        (2, 2) => ProtectedCredentialEnrollmentLaunchBindingV1::linux_arm64,
        (2, 3) => ProtectedCredentialEnrollmentLaunchBindingV1::linux_x86_64,
        _ => {
            return Err(launch_error(
                LaunchAuthorityError::UnsupportedPlatformBackend,
            ));
        }
    };
    constructor(
        *prelude.installation_identity_digest(),
        claims.release_tuple_digest,
        claims.qualification_binding_digest,
        claims.desktop_peer_binding_digest,
        claims.desktop_supervisor_generation,
        commitment,
    )
    .map_err(launch_error)
}

#[cfg(test)]
mod tests {
    use super::accepts;

    #[test]
    fn only_the_current_native_target_is_accepted() {
        let accepted: Vec<_> = [(1, 1), (2, 2), (2, 3), (1, 2), (2, 1), (2, 4), (3, 3)]
            .into_iter()
            .filter(|&(platform, architecture)| accepts(platform, architecture))
            .collect();
        let expected = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            vec![(2, 3)]
        } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
            vec![(2, 2)]
        } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            vec![(1, 1)]
        } else {
            vec![]
        };
        assert_eq!(accepted, expected);
    }
}
