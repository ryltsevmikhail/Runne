//! TEST ONLY: shared synthetic entries for multi-process credential fixtures.
//! This is neither Secret Service nor a production storage fallback. Callers
//! must use a temporary private directory and synthetic credential material.
use super::{ComboError, EntryIdentity, LinuxProviderSourceOps, SsFacadeError, SsVerifiedWrite};
use sha2::{Digest as _, Sha256};
use std::{
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Explicit test-support backend; installing it still requires the scoped seam.
pub struct DirectoryFakeSource {
    root: PathBuf,
}

impl DirectoryFakeSource {
    /// # Errors
    ///
    /// Returns `ComboError` when the root cannot be canonicalized or fails the
    /// private-directory ownership and permission checks.
    pub fn new(root: &Path) -> Result<Self, ComboError> {
        let canonical = fs::canonicalize(root).map_err(unavailable)?;
        let source = Self { root: canonical };
        source.check_root()?;
        Ok(source)
    }

    fn check_root(&self) -> Result<(), ComboError> {
        let metadata = fs::symlink_metadata(&self.root).map_err(unavailable)?;
        let uid = fs::metadata("/proc/self").map_err(unavailable)?.uid();
        if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ComboError::Ss(SsFacadeError::Unavailable));
        }
        Ok(())
    }

    fn entry(&self, identity: &EntryIdentity) -> PathBuf {
        let mut hash = Sha256::new();
        hash.update(b"runne/test-only/directory-source/v1\0");
        hash.update((identity.service.len() as u64).to_be_bytes());
        hash.update(identity.service.as_bytes());
        hash.update(identity.account.as_bytes());
        let name: String = hash
            .finalize()
            .iter()
            .fold(String::new(), |mut name, byte| {
                write!(name, "{byte:02x}").expect("writing hex into String cannot fail");
                name
            });
        self.root.join(name)
    }
}

impl LinuxProviderSourceOps for DirectoryFakeSource {
    fn read(&mut self, identity: &EntryIdentity) -> Result<Option<Zeroizing<Vec<u8>>>, ComboError> {
        self.check_root()?;
        // Linux O_NOFOLLOW | O_NONBLOCK: never follow a substituted symlink
        // or hang on a substituted FIFO, even inside a test directory.
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(0o400_000 | 0o4000)
            .open(self.entry(identity))
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unavailable(error)),
        };
        let metadata = file.metadata().map_err(unavailable)?;
        if !metadata.is_file() || metadata.len() > 1024 * 1024 {
            return Err(ComboError::Ss(SsFacadeError::Unavailable));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        if bytes.len() > 1024 * 1024 {
            return Err(ComboError::VerificationFailed);
        }
        Ok(Some(bytes))
    }

    fn write_ss_verified(
        &mut self,
        identity: &EntryIdentity,
        secret: &[u8],
    ) -> Result<SsVerifiedWrite, ComboError> {
        self.check_root()?;
        if secret.len() > 1024 * 1024 {
            return Err(ComboError::VerificationFailed);
        }
        let temporary = self.root.join(format!(
            ".write-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(unavailable)?;
            file.write_all(secret)
                .and_then(|()| file.sync_all())
                .map_err(unavailable)?;
            fs::rename(&temporary, self.entry(identity)).map_err(unavailable)?;
            if self.read(identity)?.as_deref().map(Vec::as_slice) != Some(secret) {
                return Err(ComboError::VerificationFailed);
            }
            // Implements the fixture port only; this is not SS verification.
            Ok(SsVerifiedWrite::Verified)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn delete(&mut self, identity: &EntryIdentity) -> Result<(), ComboError> {
        self.check_root()?;
        match fs::remove_file(self.entry(identity)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(unavailable(error)),
        }
    }
}

fn unavailable(_: std::io::Error) -> ComboError {
    ComboError::Ss(SsFacadeError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_instances_share_write_read_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut writer = DirectoryFakeSource::new(dir.path()).unwrap();
        let mut reader = DirectoryFakeSource::new(dir.path()).unwrap();
        let entry = EntryIdentity::new("fixture-service", "fixture-account");
        assert!(reader.read(&entry).unwrap().is_none());
        writer.write_ss_verified(&entry, b"synthetic-only").unwrap();
        assert_eq!(
            reader.read(&entry).unwrap().unwrap().as_slice(),
            b"synthetic-only"
        );
        writer.delete(&entry).unwrap();
        assert!(reader.read(&entry).unwrap().is_none());
        writer.delete(&entry).unwrap();
    }

    #[test]
    fn missing_root_and_substituted_entry_are_errors_not_absence() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut source = DirectoryFakeSource::new(dir.path()).unwrap();
        let entry = EntryIdentity::new("fixture-service", "fixture-account");
        std::os::unix::fs::symlink("missing", source.entry(&entry)).unwrap();
        assert!(source.read(&entry).is_err());
        fs::remove_file(source.entry(&entry)).unwrap();
        fs::remove_dir(dir.path()).unwrap();
        assert!(source.read(&entry).is_err());
    }
}
