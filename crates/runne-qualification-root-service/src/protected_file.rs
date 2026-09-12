use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use rustix::fs::{self, CWD, Mode, OFlags};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};
type DirectoryIdentity = (u64, u64, u32);

/// Private descriptor witness; no runtime-selected policy or key path is exported.
pub struct ProtectedFile {
    path: &'static str,
    file: File,
    identity: Identity,
    directories: Vec<DirectoryIdentity>,
    digest: [u8; 32],
    max_bytes: u64,
    secret: bool,
}

#[derive(Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl ProtectedFile {
    pub fn load(path: &'static str, max_bytes: u64, secret: bool) -> Result<Self> {
        let (file, directories) = open(path)?;
        let identity = inspect(&file, max_bytes, secret)?;
        let bytes = read(&file, max_bytes)?;
        if inspect(&file, max_bytes, secret)? != identity {
            return Err(Error);
        }
        Ok(Self {
            path,
            file,
            identity,
            directories,
            digest: Sha256::digest(&bytes).into(),
            max_bytes,
            secret,
        })
    }

    pub fn revalidate(&self) -> Result<()> {
        if inspect(&self.file, self.max_bytes, self.secret)? != self.identity {
            return Err(Error);
        }
        let current = Self::load(self.path, self.max_bytes, self.secret)?;
        if current.identity != self.identity
            || current.directories != self.directories
            || current.digest != self.digest
        {
            return Err(Error);
        }
        Ok(())
    }

    pub fn require_current_executable(&self) -> Result<()> {
        self.revalidate()?;
        runne_macos_file_security::require_current_executable_file(self.file.as_fd())
            .map_err(|_| Error)?;
        self.revalidate()
    }

    pub fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.revalidate()?;
        let bytes = read(&self.file, self.max_bytes)?;
        if Sha256::digest(&bytes).as_slice() != self.digest
            || inspect(&self.file, self.max_bytes, self.secret)? != self.identity
        {
            return Err(Error);
        }
        Ok(bytes)
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn read(mut file: &File, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    file.seek(SeekFrom::Start(0)).map_err(|_| Error)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max.checked_add(1).ok_or(Error)?)
        .read_to_end(&mut bytes)
        .map_err(|_| Error)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).map_err(|_| Error)? > max {
        return Err(Error);
    }
    Ok(bytes)
}

fn inspect(file: &File, max: u64, secret: bool) -> Result<Identity> {
    inspect_owned(file, max, secret, 0)
}

fn inspect_owned(file: &File, max: u64, secret: bool, owner: u32) -> Result<Identity> {
    runne_macos_file_security::require_no_extended_acl(file.as_fd()).map_err(|_| Error)?;
    let meta = file.metadata().map_err(|_| Error)?;
    if !meta.is_file()
        || meta.uid() != owner
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
        || meta.len() == 0
        || meta.len() > max
        || (secret && (!matches!(meta.mode() & 0o7777, 0o400 | 0o600) || meta.len() != 32))
    {
        return Err(Error);
    }
    Ok(Identity {
        device: meta.dev(),
        inode: meta.ino(),
        mode: meta.mode(),
        size: meta.len(),
        modified: (meta.mtime(), meta.mtime_nsec()),
        changed: (meta.ctime(), meta.ctime_nsec()),
    })
}

fn open(path: &str) -> Result<(File, Vec<DirectoryIdentity>)> {
    let mut parts = Path::new(path).components();
    if parts.next() != Some(Component::RootDir) {
        return Err(Error);
    }
    let parts = parts
        .map(|part| match part {
            Component::Normal(name) => Ok(name),
            _ => Err(Error),
        })
        .collect::<Result<Vec<_>>>()?;
    let (name, parents) = parts.split_last().ok_or(Error)?;
    let mut directory =
        fs::openat(CWD, "/", directory_flags(), Mode::empty()).map_err(|_| Error)?;
    let mut identities = vec![directory_identity(&directory)?];
    for parent in parents {
        directory =
            fs::openat(&directory, *parent, directory_flags(), Mode::empty()).map_err(|_| Error)?;
        identities.push(directory_identity(&directory)?);
    }
    let file = fs::openat(
        &directory,
        *name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error)?;
    Ok((File::from(file), identities))
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn directory_identity(fd: &OwnedFd) -> Result<DirectoryIdentity> {
    runne_macos_file_security::require_no_extended_acl(fd.as_fd()).map_err(|_| Error)?;
    let meta = fs::fstat(fd).map_err(|_| Error)?;
    if meta.st_uid != 0 || meta.st_mode & 0o022 != 0 {
        return Err(Error);
    }
    Ok((
        meta.st_dev.try_into().map_err(|_| Error)?,
        meta.st_ino,
        u32::from(meta.st_mode),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn seed_descriptor_rejects_acl_links_permissions_owner_and_wrong_size() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("seed");
        std::fs::write(&path, [0x42; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let file = File::open(&path).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        assert!(inspect_owned(&file, 32, true, uid).is_ok());
        assert!(inspect_owned(&file, 32, true, uid.wrapping_add(1)).is_err());
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow read"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(inspect_owned(&file, 32, true, uid).is_err());
        assert!(
            std::process::Command::new("/bin/chmod")
                .arg("-N")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        std::fs::hard_link(&path, directory.path().join("link")).unwrap();
        assert!(inspect_owned(&file, 32, true, uid).is_err());
        std::fs::remove_file(directory.path().join("link")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(inspect_owned(&file, 32, true, uid).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [0x42; 31]).unwrap();
        assert!(inspect_owned(&file, 32, true, uid).is_err());
    }
}
