use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use nix::fcntl::openat;
use nix::sys::stat::Mode;

use super::super::MacOsPackagedWriterObservationError;
use super::artifact::{ArtifactSnapshot, RetainedArtifact};
use open::{directory_flags, file_flags, open_absolute_directory, open_absolute_file};
use roles::{CONTRACT, DAEMON, DESKTOP, WRITER, fixed_application_from_writer};

mod open;
mod roles;

pub(super) use roles::PackageRole;
#[cfg(test)]
pub(crate) use roles::test_only_is_fixed_writer_locator;

pub(crate) struct PackagedWriterArtifacts {
    application_path: PathBuf,
    root: File,
    root_identity: DirectorySnapshot,
    desktop: RetainedArtifact,
    writer: RetainedArtifact,
    daemon: RetainedArtifact,
    contract: RetainedArtifact,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectorySnapshot {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

impl PackagedWriterArtifacts {
    pub(crate) fn capture_from_writer_main(
        main_executable: &Path,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        let application = fixed_application_from_writer(main_executable)?;
        let package = Self::capture(&application)?;
        package.require_main_locator(main_executable, PackageRole::Writer)?;
        Ok(package)
    }

    fn capture(application_path: &Path) -> Result<Self, MacOsPackagedWriterObservationError> {
        let root = open_absolute_directory(application_path)?;
        let root_identity = directory_snapshot(&root)?;
        valid_root(&root_identity)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        let desktop = capture_role(&root, &root_identity, DESKTOP, true)?;
        let writer = capture_role(&root, &root_identity, WRITER, true)?;
        let daemon = capture_role(&root, &root_identity, DAEMON, true)?;
        let contract = capture_role(&root, &root_identity, CONTRACT, false)?;
        let package = Self {
            application_path: application_path.to_path_buf(),
            root,
            root_identity,
            desktop,
            writer,
            daemon,
            contract,
        };
        package.require_distinct_roles()?;
        package.revalidate()?;
        Ok(package)
    }

    #[cfg(test)]
    pub(crate) fn capture_for_test(
        application_path: &Path,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        Self::capture(application_path)
    }

    pub(crate) fn revalidate(&self) -> Result<(), MacOsPackagedWriterObservationError> {
        let fresh_root = open_absolute_directory(&self.application_path)?;
        (directory_snapshot(&self.root)? == self.root_identity
            && directory_snapshot(&fresh_root)? == self.root_identity)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        for artifact in [&self.desktop, &self.writer, &self.daemon, &self.contract] {
            artifact.revalidate()?;
        }
        for (retained, components, executable) in [
            (&self.desktop, DESKTOP, true),
            (&self.writer, WRITER, true),
            (&self.daemon, DAEMON, true),
            (&self.contract, CONTRACT, false),
        ] {
            let fresh = capture_role(&fresh_root, &self.root_identity, components, executable)?;
            retained
                .matches(&fresh)
                .then_some(())
                .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        }
        self.require_distinct_roles()
    }

    pub(super) fn require_main_locator(
        &self,
        main_executable: &Path,
        role: PackageRole,
    ) -> Result<(), MacOsPackagedWriterObservationError> {
        let expected = match role {
            PackageRole::Writer => self.application_path.join("Contents/MacOS/runne"),
            PackageRole::Daemon => self.application_path.join("Contents/MacOS/runned"),
        };
        (main_executable == expected)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        let opened = open_absolute_file(main_executable)?;
        let snapshot = ArtifactSnapshot::from_file_for_match(&opened)?;
        (snapshot == *self.role(role).snapshot())
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)
    }

    #[cfg(test)]
    pub(crate) fn test_only_require_writer_main_locator(
        &self,
        main_executable: &Path,
    ) -> Result<(), MacOsPackagedWriterObservationError> {
        self.require_main_locator(main_executable, PackageRole::Writer)
    }

    pub(super) const fn role(&self, role: PackageRole) -> &RetainedArtifact {
        match role {
            PackageRole::Writer => &self.writer,
            PackageRole::Daemon => &self.daemon,
        }
    }

    fn require_distinct_roles(&self) -> Result<(), MacOsPackagedWriterObservationError> {
        let roles = [&self.desktop, &self.writer, &self.daemon, &self.contract];
        for (index, role) in roles.iter().enumerate() {
            if roles[..index]
                .iter()
                .any(|other| !role.distinct_from(other))
            {
                return Err(MacOsPackagedWriterObservationError::Rejected);
            }
        }
        Ok(())
    }
}

fn capture_role(
    root: &File,
    root_identity: &DirectorySnapshot,
    components: &[&str],
    executable: bool,
) -> Result<RetainedArtifact, MacOsPackagedWriterObservationError> {
    RetainedArtifact::capture(
        open_rooted_file(root, root_identity, components)?,
        root_identity.device,
        root_identity.uid,
        executable,
    )
}

fn open_rooted_file(
    root: &File,
    root_identity: &DirectorySnapshot,
    components: &[&str],
) -> Result<File, MacOsPackagedWriterObservationError> {
    let (name, parents) = components
        .split_last()
        .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
    let mut current = root
        .try_clone()
        .map_err(|_| MacOsPackagedWriterObservationError::Unavailable)?;
    for parent in parents {
        current = File::from(
            openat(&current, *parent, directory_flags(), Mode::empty())
                .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?,
        );
        valid_descendant(&directory_snapshot(&current)?, root_identity)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
    }
    openat(&current, *name, file_flags(), Mode::empty())
        .map(File::from)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
}

fn directory_snapshot(
    file: &File,
) -> Result<DirectorySnapshot, MacOsPackagedWriterObservationError> {
    file.metadata()
        .map(|metadata| DirectorySnapshot::from_metadata(&metadata))
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
}

impl DirectorySnapshot {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }
}

#[allow(
    clippy::missing_const_for_fn,
    reason = "lossless mode conversion is not const on the pinned MSRV"
)]
fn valid_root(snapshot: &DirectorySnapshot) -> bool {
    snapshot.mode & u32::from(libc::S_IFMT) == u32::from(libc::S_IFDIR)
        && snapshot.mode & 0o022 == 0
        && snapshot.links != 0
}

fn valid_descendant(snapshot: &DirectorySnapshot, root: &DirectorySnapshot) -> bool {
    valid_root(snapshot) && snapshot.device == root.device && snapshot.uid == root.uid
}

#[cfg(test)]
pub(crate) fn test_only_valid_directory_shape(
    root: (u64, u32),
    observed: (u64, u32, u32, u64),
) -> bool {
    let (device, uid, mode, links) = observed;
    let snapshot = DirectorySnapshot {
        device,
        inode: 1,
        uid,
        mode,
        links,
        changed_seconds: 1,
        changed_nanoseconds: 1,
        modified_seconds: 1,
        modified_nanoseconds: 1,
    };
    let root = DirectorySnapshot {
        device: root.0,
        uid: root.1,
        ..snapshot
    };
    valid_descendant(&snapshot, &root)
}
