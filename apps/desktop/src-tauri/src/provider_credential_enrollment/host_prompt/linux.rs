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
    // Production anchors the trust chain at the filesystem root.
    find_graphical_pinentry_under(system_directory, trusted_owner, Path::new("/"))
}

/// [`find_graphical_pinentry`] with an injectable chain root for tests and
/// `test-support` builds. Production callers only reach this through the
/// `/`-anchored wrapper, so production signatures and behavior are unchanged.
/// The injected root mirrors the validated session-bus injection seam: tests
/// supply a fully owner-private fixture root instead of inheriting the CI
/// workspace topology, whose foreign owner uid and umask-dependent
/// group-write bits the trust checks below must and do reject.
fn find_graphical_pinentry_under(
    system_directory: &Path,
    trusted_owner: u32,
    chain_root: &Path,
) -> Option<PathBuf> {
    if !trusted_directory_chain_under(system_directory, trusted_owner, chain_root) {
        return None;
    }
    GRAPHICAL_PINENTRY_NAMES
        .iter()
        .map(|name| system_directory.join(name))
        .find(|path| trusted_executable(path, trusted_owner))
}

fn trusted_directory_chain(path: &Path, trusted_owner: u32) -> bool {
    // Production anchors the trust chain at the filesystem root.
    trusted_directory_chain_under(path, trusted_owner, Path::new("/"))
}

/// [`trusted_directory_chain`] with an injectable chain root; see
/// [`find_graphical_pinentry_under`]. Validates every directory strictly
/// below `chain_root` with the original invariants — no symlink, a real
/// directory, owned by root or the trusted owner, no group/other write
/// access — and, exactly like the previous filesystem-root anchor, does not
/// re-validate the root itself.
fn trusted_directory_chain_under(path: &Path, trusted_owner: u32, chain_root: &Path) -> bool {
    if !path.is_absolute() || !chain_root.is_absolute() {
        return false;
    }
    let Ok(relative) = path.strip_prefix(chain_root) else {
        return false;
    };
    let mut current = PathBuf::from(chain_root);
    for component in relative.components() {
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

    /// Builds a canonical, fully owner-private fixture root with an inner
    /// `usr/bin` system directory. Every directory is created with explicit
    /// 0700 permissions (owner euid, no group/other access regardless of the
    /// ambient umask), so the injected chain satisfies exactly the production
    /// trust invariants without inheriting the CI workspace topology.
    fn owner_private_fixture_root() -> (tempfile::TempDir, PathBuf) {
        let mut binding = tempfile::Builder::new();
        let builder = binding.prefix("pinentry-fixture-");
        let root = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .and_then(|directory| builder.tempdir_in(directory).ok())
            .unwrap_or_else(|| {
                builder
                    .tempdir_in(PathBuf::from("/tmp"))
                    .expect("create fixture root")
            });
        let canonical = std::fs::canonicalize(root.path()).expect("canonical fixture root");
        std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o700))
            .expect("owner-private fixture root");
        let usr = canonical.join("usr");
        std::fs::create_dir(&usr).expect("create usr directory");
        std::fs::set_permissions(&usr, std::fs::Permissions::from_mode(0o700))
            .expect("owner-private usr directory");
        let bin = usr.join("bin");
        std::fs::create_dir(&bin).expect("create bin directory");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700))
            .expect("owner-private bin directory");
        (root, canonical)
    }

    #[test]
    fn selects_only_trusted_fixed_directory_graphical_executables() {
        let (_root, chain_root) = owner_private_fixture_root();
        let directory = chain_root.join("usr").join("bin");
        let owner = std::fs::metadata(&directory)
            .expect("fixture metadata")
            .uid();
        let terminal = directory.join("pinentry");
        std::fs::write(&terminal, "terminal backend").expect("write terminal candidate");
        let graphical = directory.join("pinentry-qt");
        std::fs::write(&graphical, "graphical backend").expect("write graphical candidate");
        std::fs::set_permissions(&graphical, std::fs::Permissions::from_mode(0o755))
            .expect("make graphical candidate executable");

        assert_eq!(
            find_graphical_pinentry_under(&directory, owner, &chain_root),
            Some(graphical.clone())
        );

        std::fs::set_permissions(&graphical, std::fs::Permissions::from_mode(0o644))
            .expect("remove executable bit");
        assert_eq!(
            find_graphical_pinentry_under(&directory, owner, &chain_root),
            None
        );
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
            &std::fs::metadata(directory).expect("fixture metadata"),
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
