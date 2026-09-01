use runne_api::{
    UpdateTrustRootV2, VerifiedSignedInstalledReleaseV2, verify_exact_signed_installed_release_v2,
};
use security_framework::os::macos::code_signing::{Flags, SecCode, SecStaticCode};

use super::{NativeSignedCodeIdentity, SignedCodeRole, match_release_code_identity};
use crate::MacOsPackagedWriterObservationError;

const RELEASE: &[u8] =
    include_bytes!("../../runne-api/tests/fixtures/signed_installed_release_v2.json");
const RELEASE_BINDING: &str = "0a0030f450326a725e260adc9a9a81056b1151b9e2e06bca2fa50752f7280781";

#[test]
fn signed_code_identities_are_matched_to_their_exact_roles() {
    let release = release();
    let desktop = identity("com.runne.desktop", 0x33);
    let writer = identity("com.runne.writer", 0x11);
    let daemon = identity("com.runne.daemon", 0x22);

    assert!(match_release_code_identity(&release, SignedCodeRole::Desktop, desktop).is_ok());
    assert!(match_release_code_identity(&release, SignedCodeRole::Writer, writer).is_ok());
    assert!(match_release_code_identity(&release, SignedCodeRole::Daemon, daemon).is_ok());
    assert!(
        match_release_code_identity(
            &release,
            SignedCodeRole::Desktop,
            identity("com.runne.writer", 0x11),
        )
        .is_err()
    );
    assert!(
        match_release_code_identity(
            &release,
            SignedCodeRole::Daemon,
            identity("com.runne.writer", 0x11),
        )
        .is_err()
    );
}

#[test]
fn exact_requirement_contains_every_validated_signed_field_and_apple_anchor() {
    let release = release();
    let identity = match_release_code_identity(
        &release,
        SignedCodeRole::Writer,
        identity("com.runne.writer", 0x11),
    )
    .unwrap();

    assert_eq!(
        identity.exact_requirement_text(),
        concat!(
            "identifier \"com.runne.writer\" and anchor apple generic and ",
            "certificate leaf[subject.OU] = \"RUNNE12345\" and ",
            "cdhash H\"1111111111111111111111111111111111111111\"",
        )
    );
}

#[test]
fn malformed_native_identity_fields_fail_closed_before_requirement_building() {
    for result in [
        NativeSignedCodeIdentity::from_parts("", "RUNNE12345", &[1; 20]),
        NativeSignedCodeIdentity::from_parts("bad identifier", "RUNNE12345", &[1; 20]),
        NativeSignedCodeIdentity::from_parts("com.runne.writer", "short", &[1; 20]),
        NativeSignedCodeIdentity::from_parts("com.runne.writer", "runne12345", &[1; 20]),
        NativeSignedCodeIdentity::from_parts("com.runne.writer", "RUNNE12345", &[1; 19]),
    ] {
        assert_eq!(
            result.err(),
            Some(MacOsPackagedWriterObservationError::Rejected)
        );
    }
}

#[test]
fn ad_hoc_static_code_is_rejected_when_signed_team_metadata_is_absent() {
    let fixture = AdHocCode::new();
    let code = fixture.static_code();

    assert_eq!(
        NativeSignedCodeIdentity::for_static_code(&code).err(),
        Some(MacOsPackagedWriterObservationError::Rejected)
    );
}

#[test]
fn ad_hoc_dynamic_code_is_rejected_when_signed_team_metadata_is_absent() {
    let code = SecCode::for_self(Flags::NONE).unwrap();

    assert_eq!(
        NativeSignedCodeIdentity::for_dynamic_code(&code).err(),
        Some(MacOsPackagedWriterObservationError::Rejected)
    );
}

#[test]
fn matched_exact_requirement_is_applied_to_static_code() {
    let fixture = AdHocCode::new();
    let matched = super::MatchedSignedCodeIdentity {
        observed: NativeSignedCodeIdentity::from_parts("dev.runne.adhoc", "RUNNE12345", &[0; 20])
            .unwrap(),
    };

    assert_eq!(
        matched.check_static_code(&fixture.static_code()).err(),
        Some(MacOsPackagedWriterObservationError::Rejected)
    );
}

#[test]
fn matched_exact_requirement_is_applied_to_dynamic_code() {
    let matched = super::MatchedSignedCodeIdentity {
        observed: NativeSignedCodeIdentity::from_parts("dev.runne.adhoc", "RUNNE12345", &[0; 20])
            .unwrap(),
    };
    let code = SecCode::for_self(Flags::NONE).unwrap();

    assert_eq!(
        matched.check_dynamic_code(&code).err(),
        Some(MacOsPackagedWriterObservationError::Rejected)
    );
}

fn identity(identifier: &str, cdhash: u8) -> NativeSignedCodeIdentity {
    NativeSignedCodeIdentity::from_parts(identifier, "RUNNE12345", &[cdhash; 20]).unwrap()
}

fn release() -> VerifiedSignedInstalledReleaseV2 {
    verify_exact_signed_installed_release_v2(RELEASE, &trust(), hex_32(RELEASE_BINDING), 100)
        .unwrap()
}

fn trust() -> UpdateTrustRootV2 {
    UpdateTrustRootV2::from_keys(
        [
            (
                "root-a",
                hex_32("43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de"),
            ),
            (
                "root-b",
                hex_32("4ed32f63bf35f0eeefcb25f28a2e1fbdc873ae2835671b0c9460f5f12e4556a8"),
            ),
            (
                "root-c",
                hex_32("884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b"),
            ),
        ],
        (
            "timestamp",
            hex_32("a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"),
        ),
        (
            "snapshot",
            hex_32("74f85cda34d1c27c4621484731e91579c3d9c6cfc0d94b281aa11e9162058aa9"),
        ),
    )
}

fn hex_32(value: &str) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("fixture uses lowercase hex"),
    }
}

struct AdHocCode {
    directory: std::path::PathBuf,
    executable: std::path::PathBuf,
}

impl AdHocCode {
    fn new() -> Self {
        static NEXT_FIXTURE: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let sequence = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "runne-b2b3i-static-adhoc-{}-{sequence}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        let executable = directory.join("adhoc");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let status = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--identifier", "dev.runne.adhoc"])
            .arg(&executable)
            .status()
            .unwrap();
        assert!(status.success());
        Self {
            directory,
            executable,
        }
    }

    fn static_code(&self) -> SecStaticCode {
        let url = core_foundation::url::CFURL::from_path(&self.executable, false).unwrap();
        SecStaticCode::from_path(&url, Flags::NONE).unwrap()
    }
}

impl Drop for AdHocCode {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
