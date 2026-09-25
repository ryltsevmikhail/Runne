use runne_platform_desktop::{LinuxGuiHostCredentialPrompt, SecureCredentialPromptError};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const SYSTEM_PINENTRY_DIRECTORY: &str = "/usr/bin";
const GRAPHICAL_PINENTRY_NAMES: [&str; 3] = ["pinentry-gnome3", "pinentry-qt", "pinentry-gtk-2"];

pub struct LinuxHostCredentialPrompt(LinuxGuiHostCredentialPrompt);

impl LinuxHostCredentialPrompt {
    pub fn new() -> Result<Self, SecureCredentialPromptError> {
        let executable = find_graphical_pinentry(Path::new(SYSTEM_PINENTRY_DIRECTORY), 0)
            .ok_or(SecureCredentialPromptError::Unavailable)?;
        LinuxGuiHostCredentialPrompt::new(
            executable,
            Duration::from_secs(30),
            Duration::from_secs(35),
        )
        .map(Self)
    }

    pub fn prompt(
        &mut self,
        request: runne_platform_desktop::SecureCredentialPromptRequest,
    ) -> Result<
        runne_platform_desktop::SecureCredentialPromptDisposition,
        SecureCredentialPromptError,
    > {
        runne_platform_desktop::SecureCredentialPromptPort::prompt(&mut self.0, request)
    }
}

fn find_graphical_pinentry(system_directory: &Path, trusted_owner: u32) -> Option<PathBuf> {
    if !trusted_directory_chain(system_directory, trusted_owner) {
        return None;
    }
    GRAPHICAL_PINENTRY_NAMES
        .iter()
        .map(|name| system_directory.join(name))
        .find(|path| trusted_executable(path, trusted_owner))
}

fn trusted_directory_chain(path: &Path, trusted_owner: u32) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut current = PathBuf::from("/");
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        current.push(name);
        let Ok(link_metadata) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        if link_metadata.file_type().is_symlink()
            || !link_metadata.is_dir()
            || (link_metadata.uid() != 0 && link_metadata.uid() != trusted_owner)
            || link_metadata.mode() & 0o022 != 0
        {
            return false;
        }
    }
    true
}

fn trusted_executable(path: &Path, trusted_owner: u32) -> bool {
    let Ok(link_metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    canonical == path
        && !link_metadata.file_type().is_symlink()
        && link_metadata.is_file()
        && link_metadata.uid() == trusted_owner
        && link_metadata.mode() & 0o111 != 0
        && link_metadata.mode() & 0o022 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_trusted_fixed_directory_graphical_executables() {
        let fixture_root = std::fs::canonicalize(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../target"),
        )
        .expect("canonical fixture root");
        let directory = tempfile::Builder::new()
            .prefix("pinentry-fixture-")
            .tempdir_in(fixture_root)
            .expect("create fixture directory");
        let directory = directory.path();
        let owner = std::os::unix::fs::MetadataExt::uid(
            &std::fs::metadata(&directory).expect("fixture metadata"),
        );
        let terminal = directory.join("pinentry");
        std::fs::write(&terminal, "terminal backend").expect("write terminal candidate");
        let graphical = directory.join("pinentry-qt");
        std::fs::write(&graphical, "graphical backend").expect("write graphical candidate");
        std::fs::set_permissions(&graphical, std::fs::Permissions::from_mode(0o755))
            .expect("make graphical candidate executable");

        assert_eq!(
            find_graphical_pinentry(&directory, owner),
            Some(graphical.clone())
        );

        std::fs::set_permissions(&graphical, std::fs::Permissions::from_mode(0o644))
            .expect("remove executable bit");
        assert_eq!(find_graphical_pinentry(&directory, owner), None);
    }

    #[test]
    fn rejects_symlinks_and_paths_owned_by_another_user() {
        let fixture_root = std::fs::canonicalize(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../target"),
        )
        .expect("canonical fixture root");
        let directory = tempfile::Builder::new()
            .prefix("pinentry-trust-fixture-")
            .tempdir_in(fixture_root)
            .expect("create fixture directory");
        let directory = directory.path();
        let owner = std::os::unix::fs::MetadataExt::uid(
            &std::fs::metadata(&directory).expect("fixture metadata"),
        );
        let candidate = directory.join("pinentry-gnome3");
        std::fs::write(&candidate, "candidate").expect("write candidate");
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o755))
            .expect("make candidate executable");
        assert!(trusted_executable(&candidate, owner));

        let link = directory.join("pinentry-qt");
        std::os::unix::fs::symlink(&candidate, &link).expect("create symlink candidate");
        assert!(!trusted_executable(&link, owner));
        assert!(!trusted_executable(&candidate, owner.saturating_add(1)));

        let redirected = directory.join("redirected");
        std::os::unix::fs::symlink(directory, &redirected).expect("create directory symlink");
        assert!(!trusted_directory_chain(&redirected, owner));
    }
}
