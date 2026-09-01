use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_owned()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn production_sources(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("module directory") {
        let path = entry.expect("module entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != "tests") {
                production_sources(&path, output);
            }
        } else if path.extension().is_some_and(|value| value == "rs") {
            output.push(path);
        }
    }
}

#[test]
fn api_signed_release_owner_has_no_native_or_authority_surface() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/provider_credential_enrollment/signed_installed_release");
    assert!(directory.is_dir(), "signed release module tree is absent");
    let facade = directory.with_extension("rs");
    let mut sources = vec![facade];
    production_sources(&directory, &mut sources);
    let forbidden = [
        "std::path",
        "Path",
        "PathBuf",
        "std::fs",
        "File",
        "OwnedFd",
        "BorrowedFd",
        "AsFd",
        "RawFd",
        "AsRawFd",
        "OwnedHandle",
        "BorrowedHandle",
        "AsHandle",
        "RawHandle",
        "AsRawHandle",
        "std::process",
        "Command",
        "Child",
        "current_exe",
        "from_parts",
        "into_authority",
        "pub fn admit",
        "pub fn mint",
        "pub trait",
        "RawDigest",
        "AuthenticatedProviderCredentialWriterSession",
        "reqwest",
        "runne_platform_desktop",
        "runne_platform_ports",
        "runne_macos_process_identity",
        "runne_native_enrollment_authority",
    ];
    for path in sources {
        let source = read(&path);
        for token in forbidden {
            assert!(
                !source.contains(token),
                "{} contains forbidden {token}",
                path.display()
            );
        }
    }
}

#[test]
fn desktop_delegates_without_duplicate_release_crypto() {
    let root = repository_root();
    let directory = root.join("crates/runne-platform-desktop/src/updater_metadata");
    assert!(
        !directory.join("verification.rs").exists(),
        "old crypto owner remains"
    );
    let paths = [
        directory.with_extension("rs"),
        directory.join("verify_v2.rs"),
        directory.join("enrollment_tuple.rs"),
        directory.join("enrollment_tuple/qualification.rs"),
    ];
    let forbidden = [
        "ed25519_dalek",
        "VerifyingKey",
        "verify_quorum",
        "gocode/native-enrollment-release-tuple/v2\\0",
        "gocode/native-enrollment-qualification-binding/v1\\0",
        "GOCODE_SIGNED_INSTALLED_RELEASE_MANIFEST_V1\\0",
        "GOCODE_SIGNED_INSTALLED_RELEASE_BINDING_V1\\0",
    ];
    for path in paths {
        let source = read(&path);
        for token in forbidden {
            assert!(
                !source.contains(token),
                "{} duplicates {token}",
                path.display()
            );
        }
    }
}

#[test]
fn only_exact_verifier_constructs_exact_installed_release() {
    let binding = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/provider_credential_enrollment/signed_installed_release/binding.rs");
    let source = read(&binding);
    assert_eq!(
        source
            .matches("pub struct VerifiedSignedInstalledReleaseV2 {")
            .count(),
        1
    );
    assert_eq!(
        source
            .matches("Ok(VerifiedSignedInstalledReleaseV2 {")
            .count(),
        1
    );
    assert!(source.contains("pub(super) fn exact("));
    assert!(!source.contains("From<SignedInstalledReleaseCandidateV2>"));
}

#[test]
fn pending_release_frame_has_one_opaque_bounded_ingress() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let frame = read(
        &crate_root.join("src/provider_credential_enrollment/signed_installed_release/frame.rs"),
    );
    let release_facade =
        read(&crate_root.join("src/provider_credential_enrollment/signed_installed_release.rs"));
    let enrollment_facade = read(&crate_root.join("src/provider_credential_enrollment.rs"));

    assert!(release_facade.contains("mod frame;"));
    assert!(release_facade.contains("pub use frame::PendingSignedInstalledReleaseMetadataV2;"));
    assert!(enrollment_facade.contains("PendingSignedInstalledReleaseMetadataV2"));
    assert_eq!(
        frame
            .matches("pub struct PendingSignedInstalledReleaseMetadataV2")
            .count(),
        1
    );
    assert_eq!(
        frame.matches("pub fn read_from<R: std::io::Read>(").count(),
        1
    );
    assert_eq!(frame.matches("pub fn ").count(), 2);
    assert_eq!(frame.matches("pub fn verify_current_pinned(").count(), 1);
    assert!(frame.contains("expected: DigestEqualityMatcherV1"));
    assert!(!frame.contains("pub fn verify_current_pinned(\n        self,\n        trust:"));
    assert!(!frame.contains("pub fn verify_current_pinned(\n        self,\n        now:"));
    assert!(!frame.contains("expected: [u8; 32]"));
    assert_eq!(
        frame
            .matches("Ok(PendingSignedInstalledReleaseMetadataV2 {")
            .count(),
        1
    );
    assert!(frame.contains("const MAGIC: &[u8; 8] = b\"GCRMDV2\\0\";"));
    assert!(frame.contains("const MAX_PAYLOAD_BYTES: usize = 524_288;"));
    let bound_check = frame
        .find("if payload_length > MAX_PAYLOAD_BYTES")
        .expect("payload bound check");
    let allocation = frame
        .find("vec![0_u8; payload_length]")
        .expect("exact payload allocation");
    assert!(
        bound_check < allocation,
        "payload allocated before bound check"
    );
    for forbidden in [
        "#[derive(",
        "pub type PendingSignedInstalledReleaseMetadataV2",
        "pub canonical_metadata",
        "Clone for PendingSignedInstalledReleaseMetadataV2",
        "Copy for PendingSignedInstalledReleaseMetadataV2",
        "Debug for PendingSignedInstalledReleaseMetadataV2",
        "Default for PendingSignedInstalledReleaseMetadataV2",
        "Serialize for PendingSignedInstalledReleaseMetadataV2",
        "Deserialize<",
        "pub fn new",
        "pub fn from_parts",
        "impl From<",
        "impl Into<",
        "pub fn payload",
        "pub fn bytes",
        "pub fn raw",
        "pub fn frame",
        "pub fn digest",
        "pub fn path",
        "pub fn pid",
        "pub fn audit_token",
        "pub fn candidate",
        "pub fn metadata",
        "pub fn verify_exact",
        "pub fn authenticate",
        "pub fn admit",
        "pub fn mint",
        "pub fn into_authority",
        "pub fn trust",
        "pub fn now",
        "pub trait",
        "Serialize",
        "Deserialize",
        "AsFd",
        "AsRawFd",
        "IntoRawFd",
    ] {
        assert!(
            !frame.contains(forbidden),
            "pending release frame exposes forbidden surface: {forbidden}"
        );
    }
}
