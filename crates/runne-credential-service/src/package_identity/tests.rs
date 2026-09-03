use std::path::Path;

use super::{ObservedIdentity, configurations, package_executables};
use runne_macos_xpc::{CredentialServiceEndpointRole, CredentialServiceXpcError};

fn identity(identifier: &str, byte: u8) -> ObservedIdentity {
    ObservedIdentity {
        identifier: identifier.into(),
        team_identifier: "758F9Z45SR".into(),
        cdhash: [byte; 20],
    }
}

#[test]
fn exact_installed_layout_resolves_all_four_executables() {
    let service = Path::new(
        "/Applications/Runne.app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service",
    );
    let paths = package_executables(service).unwrap();
    assert_eq!(paths.service, service);
    assert_eq!(
        paths.desktop,
        Path::new("/Applications/Runne.app/Contents/MacOS/runne-desktop")
    );
    assert_eq!(
        paths.runtime,
        Path::new("/Applications/Runne.app/Contents/MacOS/runned")
    );
    assert_eq!(
        paths.writer,
        Path::new("/Applications/Runne.app/Contents/MacOS/runne")
    );
}

#[test]
fn moved_or_skewed_helper_layout_is_rejected() {
    for path in [
        "/Applications/Other.app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service",
        "/Applications/Runne.app/Contents/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service",
        "/Applications/Runne.app/Contents/Library/Helpers/Other.app/Contents/MacOS/runne-credential-service",
        "/Applications/Runne.app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/other",
    ] {
        assert_eq!(
            package_executables(Path::new(path)).err(),
            Some(CredentialServiceXpcError::Rejected),
        );
    }
}

#[test]
fn package_identities_build_exact_distinct_role_configuration() {
    let identities = (
        identity("com.runne.credential-service", 1),
        identity("com.runne.desktop", 2),
        identity("runned", 3),
        identity("runne", 4),
    );
    let configurations =
        configurations(&identities.0, &identities.1, &identities.2, &identities.3).unwrap();
    assert_eq!(
        configurations.map(|configuration| configuration.role()),
        [
            CredentialServiceEndpointRole::Desktop,
            CredentialServiceEndpointRole::Runtime,
            CredentialServiceEndpointRole::Writer,
        ],
    );
}

#[test]
fn identifier_team_or_reused_service_identity_fails_closed() {
    let mut wrong_team = identity("com.runne.desktop", 2);
    wrong_team.team_identifier = "AAAAAAAAAA".into();
    assert!(
        configurations(
            &identity("com.runne.credential-service", 1),
            &wrong_team,
            &identity("runned", 3),
            &identity("runne", 4),
        )
        .is_err()
    );
    assert!(
        configurations(
            &identity("com.runne.credential-service", 1),
            &identity("com.runne.desktop", 1),
            &identity("runned", 3),
            &identity("runne", 4),
        )
        .is_err()
    );
}
