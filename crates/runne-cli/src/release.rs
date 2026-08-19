//! Closed, side-effect-free release-promotion plan commands.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;

use runne_release_authority::ProductionAuthorityStatus;

use super::CliError;

const RELEASE_HELP: &str =
    "release: rc1 qualify | rc2 authorize | rc2 verify | rc3 authorize (only --dry-run)";

pub fn run(mut arguments: VecDeque<OsString>) -> Result<String, CliError> {
    if arguments.pop_front().as_deref() != Some(std::ffi::OsStr::new("release")) {
        return Err(CliError::Usage);
    }
    if arguments
        .front()
        .is_some_and(|argument| argument == "--help")
    {
        arguments.pop_front();
        return arguments
            .is_empty()
            .then(|| RELEASE_HELP.into())
            .ok_or(CliError::Usage);
    }
    let stage = text(&mut arguments)?;
    let operation = text(&mut arguments)?;
    if operation == "--help" {
        return help(&stage, &arguments);
    }
    let (name, flags) = command(&stage, &operation)?;
    if arguments
        .front()
        .is_some_and(|argument| argument == "--help")
    {
        arguments.pop_front();
        return arguments
            .is_empty()
            .then(|| format!("{name}: {}", flags.join(" ")))
            .ok_or(CliError::Usage);
    }
    let input_digests = digests(&mut arguments, flags)?;
    serde_json::to_string(&serde_json::json!({
        "external_effects": [],
        "input_digests": input_digests,
        "operation": name,
        "status": ProductionAuthorityStatus::NotProvisioned.as_code(),
    }))
    .map_err(|_| CliError::Runtime)
}

fn help(stage: &str, arguments: &VecDeque<OsString>) -> Result<String, CliError> {
    if !arguments.is_empty() {
        return Err(CliError::Usage);
    }
    let (_, flags) = match stage {
        "rc1" => command(stage, "qualify")?,
        "rc2" | "rc3" => command(stage, "authorize")?,
        _ => return Err(CliError::Usage),
    };
    Ok(format!("release {stage}: {}", flags.join(" ")))
}

fn command(
    stage: &str,
    operation: &str,
) -> Result<(&'static str, &'static [&'static str]), CliError> {
    match (stage, operation) {
        ("rc1", "qualify") => Ok((
            "release.rc1.qualify",
            &[
                "--dry-run",
                "--subject-sha256",
                "--matrix-sha256",
                "--bootstrap-sha256",
                "--candidate-sha256",
                "--policy-sha256",
            ],
        )),
        ("rc2", "authorize") => Ok((
            "release.rc2.authorize",
            &[
                "--dry-run",
                "--candidate-sha256",
                "--rc1-decision-sha256",
                "--unsigned-candidate-manifest-sha256",
                "--linux-pre-sign-sha256",
                "--linux-pre-sign-length",
                "--windows-pre-sign-sha256",
                "--windows-pre-sign-length",
                "--workflow-sha256",
                "--effect-namespace",
                "--effect-generation",
                "--signing-policy-sha256",
            ],
        )),
        ("rc2", "verify") => Ok((
            "release.rc2.verify",
            &[
                "--dry-run",
                "--candidate-sha256",
                "--signed-envelope-inventory-sha256",
                "--threshold-update-metadata-set-sha256",
                "--verification-report-sha256",
            ],
        )),
        ("rc3", "authorize") => Ok((
            "release.rc3.authorize",
            &[
                "--dry-run",
                "--candidate-sha256",
                "--signed-envelope-inventory-sha256",
                "--threshold-update-metadata-set-sha256",
                "--verification-report-sha256",
                "--publication-manifest-sha256",
            ],
        )),
        _ => Err(CliError::Usage),
    }
}

fn digests(
    arguments: &mut VecDeque<OsString>,
    flags: &[&str],
) -> Result<BTreeMap<String, String>, CliError> {
    required(arguments, flags[0])?;
    let mut values = BTreeMap::new();
    for flag in &flags[1..] {
        required(arguments, flag)?;
        let value = text(arguments)?;
        if !valid_value(flag, &value) {
            return Err(CliError::Usage);
        }
        values.insert(flag.trim_start_matches("--").into(), value);
    }
    arguments
        .is_empty()
        .then_some(values)
        .ok_or(CliError::Usage)
}

fn required(arguments: &mut VecDeque<OsString>, flag: &str) -> Result<(), CliError> {
    (arguments.pop_front().as_deref() == Some(std::ffi::OsStr::new(flag)))
        .then_some(())
        .ok_or(CliError::Usage)
}

fn text(arguments: &mut VecDeque<OsString>) -> Result<String, CliError> {
    arguments
        .pop_front()
        .ok_or(CliError::Usage)?
        .into_string()
        .map_err(|_| CliError::Usage)
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase() && byte <= b'f')
}

fn valid_value(flag: &str, value: &str) -> bool {
    match flag {
        "--linux-pre-sign-length" | "--windows-pre-sign-length" | "--effect-generation" => value
            .parse::<u64>()
            .is_ok_and(|number| number != 0 && number.to_string() == value),
        "--effect-namespace" => {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        }
        _ => sha256(value),
    }
}

/// Maximum bytes accepted for one raw release artifact.
const MAX_ARTIFACT_BYTES: u64 = 1 << 20;

/// Safe bounded nofollow read of one raw release artifact.
///
/// Rejects symlinks, directories, FIFOs, devices and oversized inputs before any
/// parsing. Returns the exact regular-file bytes otherwise.
#[cfg(unix)]
#[allow(dead_code)] // Wired into the full raw-chain dry-run verification (task-3).
pub fn read_artifact(path: &std::path::Path) -> Result<Vec<u8>, CliError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let meta = std::fs::symlink_metadata(path).map_err(|_| CliError::AuthorityArtifactIo)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(CliError::AuthorityVerifyFailed);
    }
    if meta.len() > MAX_ARTIFACT_BYTES {
        return Err(CliError::AuthorityVerifyFailed);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| CliError::AuthorityVerifyFailed)?;
    let mut bytes = Vec::new();
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::AuthorityArtifactIo)?;
    if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err(CliError::AuthorityVerifyFailed);
    }
    Ok(bytes)
}

#[cfg(all(test, unix))]
mod boundary_tests {
    use super::{CliError, read_artifact};

    #[test]
    fn rejects_symlink_directory_and_oversize_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();

        let regular = path.join("regular.json");
        std::fs::write(&regular, b"{\"schema_version\":\"x\"}\n").unwrap();
        assert!(read_artifact(&regular).is_ok());

        let link = path.join("link.json");
        std::os::unix::fs::symlink(&regular, &link).unwrap();
        assert!(matches!(
            read_artifact(&link),
            Err(CliError::AuthorityVerifyFailed)
        ));

        assert!(matches!(
            read_artifact(path),
            Err(CliError::AuthorityVerifyFailed)
        ));

        let oversized = vec![b'0'; 1 << 21];
        std::fs::write(path.join("big.json"), &oversized).unwrap();
        assert!(matches!(
            read_artifact(&path.join("big.json")),
            Err(CliError::AuthorityVerifyFailed)
        ));
    }
}
