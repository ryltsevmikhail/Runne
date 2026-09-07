use runne_api::VerifiedSignedInstalledReleaseV2;
use std::str::FromStr as _;

use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement, SecStaticCode};

use crate::MacOsPackagedWriterObservationError;
use crate::packaged_writer_observation::package::PackagedWriterArtifacts;
use crate::packaged_writer_observation::process::PackagedLiveProcessObservation;

pub mod service;
mod signing_information;

struct NativeSignedCodeIdentity {
    identifier: String,
    team_identifier: String,
    cdhash: [u8; 20],
}

impl NativeSignedCodeIdentity {
    fn for_static_code(code: &SecStaticCode) -> Result<Self, MacOsPackagedWriterObservationError> {
        signing_information::copy_static_identity(code)
    }

    fn for_dynamic_code(code: &SecCode) -> Result<Self, MacOsPackagedWriterObservationError> {
        signing_information::copy_dynamic_identity(code)
    }

    fn from_parts(
        identifier: impl Into<String>,
        team_identifier: impl Into<String>,
        cdhash: &[u8],
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        let identifier = identifier.into();
        let team_identifier = team_identifier.into();
        let valid_identifier = !identifier.is_empty()
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
        let valid_team = team_identifier.len() == 10
            && team_identifier
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
        let cdhash = <[u8; 20]>::try_from(cdhash)
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        (valid_identifier && valid_team)
            .then_some(Self {
                identifier,
                team_identifier,
                cdhash,
            })
            .ok_or(MacOsPackagedWriterObservationError::Rejected)
    }

    fn cdhash_hex(&self) -> String {
        encode_cdhash(&self.cdhash)
    }
}

struct MatchedSignedCodeIdentity {
    observed: NativeSignedCodeIdentity,
}

impl MatchedSignedCodeIdentity {
    fn exact_requirement_text(&self) -> String {
        format!(
            "identifier \"{}\" and anchor apple generic and certificate leaf[subject.OU] = \"{}\" and cdhash H\"{}\"",
            self.observed.identifier,
            self.observed.team_identifier,
            self.observed.cdhash_hex(),
        )
    }

    fn check_static_code(
        &self,
        code: &SecStaticCode,
    ) -> Result<(), MacOsPackagedWriterObservationError> {
        let requirement = SecRequirement::from_str(&self.exact_requirement_text())
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        code.check_validity(
            Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
            &requirement,
        )
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
    }

    fn check_dynamic_code(
        &self,
        code: &SecCode,
    ) -> Result<(), MacOsPackagedWriterObservationError> {
        let requirement = SecRequirement::from_str(&self.exact_requirement_text())
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        code.check_validity(
            Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
            &requirement,
        )
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
    }
}

#[derive(Clone, Copy)]
enum SignedCodeRole {
    Desktop,
    Writer,
    Daemon,
}

pub fn match_retained_code_identities(
    release: &VerifiedSignedInstalledReleaseV2,
    package: &PackagedWriterArtifacts,
    writer: &PackagedLiveProcessObservation,
    daemon: &PackagedLiveProcessObservation,
) -> Result<(), MacOsPackagedWriterObservationError> {
    #[cfg(feature = "test-support")]
    if runne_api::test_support::local_native_enrollment_enabled() {
        return match_local_code_identities(package, writer, daemon);
    }
    let desktop_path = package.desktop_main_executable()?;
    let desktop_url = core_foundation::url::CFURL::from_path(&desktop_path, false)
        .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
    let desktop = SecStaticCode::from_path(&desktop_url, Flags::NONE)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
    match_static_code(release, SignedCodeRole::Desktop, &desktop)?;
    match_dynamic_code(release, SignedCodeRole::Writer, writer.native_code().code())?;
    match_dynamic_code(release, SignedCodeRole::Daemon, daemon.native_code().code())
}

#[cfg(feature = "test-support")]
fn match_local_code_identities(
    package: &PackagedWriterArtifacts,
    writer: &PackagedLiveProcessObservation,
    daemon: &PackagedLiveProcessObservation,
) -> Result<(), MacOsPackagedWriterObservationError> {
    let desktop_path = package.desktop_main_executable()?;
    let writer_path = package.local_writer_main_executable();
    let daemon_path = package.local_daemon_main_executable();
    let requirements = [
        local_requirement(&desktop_path)?,
        local_requirement(&writer_path)?,
        local_requirement(&daemon_path)?,
    ];
    if requirements[0] == requirements[1]
        || requirements[0] == requirements[2]
        || requirements[1] == requirements[2]
    {
        return Err(MacOsPackagedWriterObservationError::Rejected);
    }
    let desktop_url = core_foundation::url::CFURL::from_path(&desktop_path, false)
        .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
    let desktop = SecStaticCode::from_path(&desktop_url, Flags::NONE)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
    check_local_static(&desktop, &requirements[0])?;
    check_local_dynamic(writer.native_code().code(), &requirements[1])?;
    check_local_dynamic(daemon.native_code().code(), &requirements[2])
}

#[cfg(feature = "test-support")]
fn local_requirement(
    path: &std::path::Path,
) -> Result<String, MacOsPackagedWriterObservationError> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "-r", "-", "--"])
        .arg(path)
        .output()
        .map_err(|_| MacOsPackagedWriterObservationError::Unavailable)?;
    if !output.status.success() {
        return Err(MacOsPackagedWriterObservationError::Rejected);
    }
    std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("designated => ")
                    .or_else(|| line.strip_prefix("# designated => "))
            })
        })
        .map(str::to_owned)
        .ok_or(MacOsPackagedWriterObservationError::Rejected)
}

#[cfg(feature = "test-support")]
fn check_local_static(
    code: &SecStaticCode,
    requirement: &str,
) -> Result<(), MacOsPackagedWriterObservationError> {
    let requirement = SecRequirement::from_str(requirement)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
}

#[cfg(feature = "test-support")]
fn check_local_dynamic(
    code: &SecCode,
    requirement: &str,
) -> Result<(), MacOsPackagedWriterObservationError> {
    let requirement = SecRequirement::from_str(requirement)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
}

fn match_static_code(
    release: &VerifiedSignedInstalledReleaseV2,
    role: SignedCodeRole,
    code: &SecStaticCode,
) -> Result<(), MacOsPackagedWriterObservationError> {
    let observed = NativeSignedCodeIdentity::for_static_code(code)?;
    let matched = match_release_code_identity(release, role, observed)?;
    matched.check_static_code(code)
}

fn match_dynamic_code(
    release: &VerifiedSignedInstalledReleaseV2,
    role: SignedCodeRole,
    code: &SecCode,
) -> Result<(), MacOsPackagedWriterObservationError> {
    let observed = NativeSignedCodeIdentity::for_dynamic_code(code)?;
    let matched = match_release_code_identity(release, role, observed)?;
    matched.check_dynamic_code(code)
}

fn match_release_code_identity(
    release: &VerifiedSignedInstalledReleaseV2,
    role: SignedCodeRole,
    observed: NativeSignedCodeIdentity,
) -> Result<MatchedSignedCodeIdentity, MacOsPackagedWriterObservationError> {
    let cdhash = observed.cdhash_hex();
    let matches = match role {
        SignedCodeRole::Desktop => release.matches_desktop_code_identity(
            &observed.identifier,
            &observed.team_identifier,
            &cdhash,
        ),
        SignedCodeRole::Writer => release.matches_writer_code_identity(
            &observed.identifier,
            &observed.team_identifier,
            &cdhash,
        ),
        SignedCodeRole::Daemon => release.matches_daemon_code_identity(
            &observed.identifier,
            &observed.team_identifier,
            &cdhash,
        ),
    };
    matches
        .then_some(MatchedSignedCodeIdentity { observed })
        .ok_or(MacOsPackagedWriterObservationError::Rejected)
}

fn encode_cdhash(cdhash: &[u8; 20]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(40);
    for byte in cdhash {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
#[path = "signed_code_identity_tests.rs"]
mod tests;
