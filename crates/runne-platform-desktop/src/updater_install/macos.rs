use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{NativeUpdateInstallError, UpdateArtifactKind};

const CODESIGN: &str = "/usr/bin/codesign";
const DITTO: &str = "/usr/bin/ditto";
const HDIUTIL: &str = "/usr/bin/hdiutil";
const SPCTL: &str = "/usr/sbin/spctl";
const EXECUTABLES: [&str; 3] = ["runne-desktop", "runne", "runned"];

pub fn install(
    kind: UpdateArtifactKind,
    staged: &Path,
    current_executable: &Path,
) -> Result<(), NativeUpdateInstallError> {
    if kind != UpdateArtifactKind::MacDmg {
        return Err(NativeUpdateInstallError::UnsupportedPlatform);
    }
    let bundle = current_executable
        .ancestors()
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("app"))
        .ok_or(NativeUpdateInstallError::InvalidArtifact)?;
    let bundle_name = bundle
        .file_name()
        .ok_or(NativeUpdateInstallError::InvalidArtifact)?;
    let stem = bundle
        .file_stem()
        .ok_or(NativeUpdateInstallError::InvalidArtifact)?;
    let parent = bundle
        .parent()
        .ok_or(NativeUpdateInstallError::InvalidArtifact)?;
    let process = std::process::id();
    let mount = std::env::temp_dir().join(format!("runne-update-mount-{process}"));
    let replacement = parent.join(format!(".{}.new-{process}.app", stem.to_string_lossy()));
    let backup = parent.join(format!(".{}.old-{process}.app", stem.to_string_lossy()));
    if mount.exists() || replacement.exists() || backup.exists() {
        return Err(NativeUpdateInstallError::InvalidArtifact);
    }
    fs::create_dir(&mount).map_err(|_| NativeUpdateInstallError::InstallerFailed)?;
    let mut attached = false;
    let result = (|| {
        run(Command::new(HDIUTIL).args([
            OsStr::new("attach"),
            OsStr::new("-nobrowse"),
            OsStr::new("-readonly"),
            OsStr::new("-mountpoint"),
            mount.as_os_str(),
            staged.as_os_str(),
        ]))?;
        attached = true;
        let mounted_bundle = mount.join(bundle_name);
        run(Command::new(DITTO).args([mounted_bundle.as_os_str(), replacement.as_os_str()]))?;
        admit_replacement(&replacement, &mut LiveRunner)?;
        fs::rename(bundle, &backup).map_err(|_| NativeUpdateInstallError::InstallerFailed)?;
        if fs::rename(&replacement, bundle).is_err() {
            let _ = fs::rename(&backup, bundle);
            return Err(NativeUpdateInstallError::InstallerFailed);
        }
        let _ = fs::remove_dir_all(&backup);
        Ok(())
    })();
    if attached {
        let _ = Command::new(HDIUTIL)
            .args([OsStr::new("detach"), mount.as_os_str()])
            .status();
    }
    let _ = fs::remove_dir(&mount);
    if result.is_err() {
        let _ = fs::remove_dir_all(&replacement);
    }
    result
}

trait NativeCommandRunner {
    fn execute(
        &mut self,
        program: &'static str,
        arguments: &[&OsStr],
    ) -> Result<(), NativeUpdateInstallError>;
}

struct LiveRunner;

impl NativeCommandRunner for LiveRunner {
    fn execute(
        &mut self,
        program: &'static str,
        arguments: &[&OsStr],
    ) -> Result<(), NativeUpdateInstallError> {
        run(Command::new(program).args(arguments))
    }
}

fn admit_replacement(
    bundle: &Path,
    runner: &mut impl NativeCommandRunner,
) -> Result<(), NativeUpdateInstallError> {
    if bundle.is_symlink() || !bundle.is_dir() {
        return Err(NativeUpdateInstallError::InvalidArtifact);
    }
    let macos = bundle.join("Contents/MacOS");
    let mut observed: Vec<OsString> = fs::read_dir(&macos)
        .map_err(|_| NativeUpdateInstallError::InvalidArtifact)?
        .map(|entry| entry.map(|value| value.file_name()))
        .collect::<Result<_, _>>()
        .map_err(|_| NativeUpdateInstallError::InvalidArtifact)?;
    observed.sort();
    let mut expected: Vec<OsString> = EXECUTABLES.iter().map(OsString::from).collect();
    expected.sort();
    if observed != expected {
        return Err(NativeUpdateInstallError::InvalidArtifact);
    }
    for name in EXECUTABLES {
        let executable = macos.join(name);
        if !regular_file(&executable) {
            return Err(NativeUpdateInstallError::InvalidArtifact);
        }
        runner.execute(
            CODESIGN,
            &[
                OsStr::new("--verify"),
                OsStr::new("--strict"),
                executable.as_os_str(),
            ],
        )?;
    }
    runner.execute(
        CODESIGN,
        &[
            OsStr::new("--verify"),
            OsStr::new("--strict"),
            bundle.as_os_str(),
        ],
    )?;
    runner.execute(
        SPCTL,
        &[
            OsStr::new("--assess"),
            OsStr::new("--type"),
            OsStr::new("execute"),
            bundle.as_os_str(),
        ],
    )
}

fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|value| value.file_type().is_file())
}

fn run(command: &mut Command) -> Result<(), NativeUpdateInstallError> {
    command
        .status()
        .map_err(|_| NativeUpdateInstallError::InstallerFailed)?
        .success()
        .then_some(())
        .ok_or(NativeUpdateInstallError::InstallerFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingRunner {
        commands: Vec<(String, Vec<String>)>,
        fail_at: Option<usize>,
    }

    impl NativeCommandRunner for RecordingRunner {
        fn execute(
            &mut self,
            program: &'static str,
            arguments: &[&OsStr],
        ) -> Result<(), NativeUpdateInstallError> {
            let index = self.commands.len();
            self.commands.push((
                program.into(),
                arguments
                    .iter()
                    .map(|value| value.to_string_lossy().into())
                    .collect(),
            ));
            if self.fail_at == Some(index) {
                Err(NativeUpdateInstallError::InstallerFailed)
            } else {
                Ok(())
            }
        }
    }

    fn replacement() -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join(".Runne.new-1.app");
        let macos = bundle.join("Contents/MacOS");
        fs::create_dir_all(&macos).unwrap();
        for name in EXECUTABLES {
            fs::write(macos.join(name), b"signed").unwrap();
        }
        (directory, bundle)
    }

    #[test]
    fn replacement_admission_is_component_bundle_then_gatekeeper() {
        let (_directory, bundle) = replacement();
        let mut runner = RecordingRunner::default();
        admit_replacement(&bundle, &mut runner).unwrap();
        let executable = |name: &str| {
            bundle
                .join("Contents/MacOS")
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        let bundle = bundle.to_string_lossy().into_owned();
        assert_eq!(
            runner.commands,
            vec![
                codesign_command(executable("runne-desktop")),
                codesign_command(executable("runne")),
                codesign_command(executable("runned")),
                codesign_command(bundle.clone()),
                (
                    SPCTL.into(),
                    vec!["--assess".into(), "--type".into(), "execute".into(), bundle]
                ),
            ]
        );
    }

    #[test]
    fn replacement_admission_stops_on_signature_or_gatekeeper_failure() {
        for fail_at in [0, 4] {
            let (_directory, bundle) = replacement();
            let mut runner = RecordingRunner {
                fail_at: Some(fail_at),
                ..RecordingRunner::default()
            };
            assert_eq!(
                admit_replacement(&bundle, &mut runner),
                Err(NativeUpdateInstallError::InstallerFailed)
            );
            assert_eq!(runner.commands.len(), fail_at + 1);
        }
    }

    fn codesign_command(path: String) -> (String, Vec<String>) {
        (
            CODESIGN.into(),
            vec!["--verify".into(), "--strict".into(), path],
        )
    }
}
