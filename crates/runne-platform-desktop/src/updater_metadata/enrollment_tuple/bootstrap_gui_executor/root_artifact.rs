use std::fs::File;
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;

use rustix::fs::{Mode, OFlags, open, openat};

use crate::updater_metadata::enrollment_measurement::OpenedNativeEnrollmentFile;

const DIRECTORIES: [&str; 4] = ["opt", "gocode", "sourcecraft", "bin"];
const EXECUTABLE: &str = "runne-qualification-root-service";
type DirectoryIdentity = (u64, u64, u32);

pub(in crate::updater_metadata) struct RootBootstrapArtifact {
    file: OpenedNativeEnrollmentFile,
    directories: Vec<DirectoryIdentity>,
}

impl RootBootstrapArtifact {
    pub(super) fn load() -> Option<Self> {
        let mut current = File::from(open("/", directory_flags(), Mode::empty()).ok()?);
        let mut directories = vec![inspect_directory(&current)?];
        for name in DIRECTORIES {
            current = File::from(openat(&current, name, directory_flags(), Mode::empty()).ok()?);
            directories.push(inspect_directory(&current)?);
        }
        let file = File::from(
            openat(
                &current,
                EXECUTABLE,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .ok()?,
        );
        inspect_root_file(&file)?;
        Some(Self {
            file: OpenedNativeEnrollmentFile::new(file).ok()?,
            directories,
        })
    }

    pub(in crate::updater_metadata) fn matches_digest(&self, expected: &str) -> Option<()> {
        let before = Self::load()?;
        if self.directories != before.directories || !self.file.matches_opened(&before.file).ok()? {
            return None;
        }
        if self.file.measure().ok()? != expected {
            return None;
        }
        let after = Self::load()?;
        (self.directories == after.directories
            && self.file.matches_opened(&after.file).ok()?
            && after.file.measure().ok()? == expected)
            .then_some(())
    }
}

fn inspect_directory(file: &File) -> Option<DirectoryIdentity> {
    runne_macos_file_security::require_no_extended_acl(file.as_fd()).ok()?;
    let meta = file.metadata().ok()?;
    (meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0).then_some((
        meta.dev(),
        meta.ino(),
        meta.mode(),
    ))
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn inspect_root_file(file: &File) -> Option<()> {
    let meta = file.metadata().ok()?;
    runne_macos_file_security::require_no_extended_acl(file.as_fd()).ok()?;
    (meta.uid() == 0 && meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o022 == 0)
        .then_some(())
}

#[cfg(test)]
mod tests {
    use super::{File, inspect_directory, inspect_root_file};
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn root_artifact_checks_distinguish_root_files_directories_and_writable_fixtures() {
        let directory = File::open("/").unwrap();
        assert!(inspect_directory(&directory).is_some());
        assert!(inspect_root_file(&directory).is_none());
        let executable = File::open("/usr/bin/true").unwrap();
        assert!(inspect_root_file(&executable).is_some());
        assert!(inspect_directory(&executable).is_none());
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(inspect_root_file(file.as_file()).is_none());
    }
}
