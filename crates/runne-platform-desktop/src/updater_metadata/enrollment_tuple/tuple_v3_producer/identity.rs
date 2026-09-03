use std::path::Path;

use runne_api::{MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleError};

use super::{CodeIdentityObserver, CodeIdentityRole};

pub(super) struct NativeCodeIdentityObserver;

#[cfg(target_os = "macos")]
impl CodeIdentityObserver for NativeCodeIdentityObserver {
    fn verify_bundle(&self, path: &Path) -> Result<(), NativeEnrollmentTupleError> {
        verify_codesign(
            path,
            &["--verify", "--deep", "--strict", "--verbose=4", "--"],
        )
    }

    fn observe(
        &self,
        _role: CodeIdentityRole,
        path: &Path,
    ) -> Result<MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleError> {
        verify_codesign(path, &["--verify", "--strict", "--verbose=4", "--"])?;
        let displayed = std::process::Command::new("/usr/bin/codesign")
            .args(["--display", "--verbose=4", "--"])
            .arg(path)
            .output()
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !displayed.status.success() {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let mut bytes = displayed.stdout;
        bytes.extend_from_slice(&displayed.stderr);
        parse_identity(&bytes)
    }
}

#[cfg(not(target_os = "macos"))]
impl CodeIdentityObserver for NativeCodeIdentityObserver {
    fn verify_bundle(&self, _path: &Path) -> Result<(), NativeEnrollmentTupleError> {
        Err(NativeEnrollmentTupleError::Rejected)
    }

    fn observe(
        &self,
        _role: CodeIdentityRole,
        _path: &Path,
    ) -> Result<MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleError> {
        Err(NativeEnrollmentTupleError::Rejected)
    }
}

#[cfg(target_os = "macos")]
fn verify_codesign(path: &Path, arguments: &[&str]) -> Result<(), NativeEnrollmentTupleError> {
    std::process::Command::new("/usr/bin/codesign")
        .args(arguments)
        .arg(path)
        .output()
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?
        .status
        .success()
        .then_some(())
        .ok_or(NativeEnrollmentTupleError::Rejected)
}

fn parse_identity(
    bytes: &[u8],
) -> Result<MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleError> {
    let text = std::str::from_utf8(bytes).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let identifier = exact_field(text, "Identifier=")?;
    let team = exact_field(text, "TeamIdentifier=")?;
    let cdhash = exact_field(text, "CDHash=")?.to_ascii_lowercase();
    MacOsCodeIdentityExpectationV1::new(identifier, team, cdhash)
        .ok_or(NativeEnrollmentTupleError::Rejected)
}

fn exact_field<'a>(text: &'a str, prefix: &str) -> Result<&'a str, NativeEnrollmentTupleError> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = values.next().ok_or(NativeEnrollmentTupleError::Rejected)?;
    (!value.is_empty() && values.next().is_none())
        .then_some(value)
        .ok_or(NativeEnrollmentTupleError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codesign_identity_parser_requires_one_complete_identity() {
        let identity = parse_identity(
            b"Executable=/tmp/runne\nIdentifier=com.runne.desktop\nTeamIdentifier=758F9Z45SR\nCDHash=ABCDEF0123456789ABCDEF0123456789ABCDEF01\n",
        )
        .unwrap();
        assert_eq!(identity.identifier(), "com.runne.desktop");
        assert_eq!(identity.team_identifier(), "758F9Z45SR");
        assert_eq!(
            identity.cdhash(),
            "abcdef0123456789abcdef0123456789abcdef01"
        );
        for invalid in [
            "Identifier=com.runne.desktop\nCDHash=abcdef0123456789abcdef0123456789abcdef01\n",
            "Identifier=com.runne.desktop\nTeamIdentifier=not set\nCDHash=abcdef0123456789abcdef0123456789abcdef01\n",
            "Identifier=com.runne.desktop\nIdentifier=runne\nTeamIdentifier=758F9Z45SR\nCDHash=abcdef0123456789abcdef0123456789abcdef01\n",
        ] {
            assert!(parse_identity(invalid.as_bytes()).is_err());
        }
    }
}
