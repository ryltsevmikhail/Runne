use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;

use rand::{RngCore as _, rngs::OsRng};
use rustix::fs::{FileType, Mode, OFlags, fstat, fsync, open, openat, renameat};

use super::{FixtureJournalKey, decode_key_ref, encode_key_ref};
use runne_secure_store::ProviderJournalKeyRef;

const KEY_NAME: &str = "fixture-provider-journal-key.bin";
const KEY_SIZE: usize = 80;

pub(super) fn open_runtime_root(root: &Path) -> std::io::Result<File> {
    let directory = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::other)?;
    validate_directory(&directory)?;
    Ok(File::from(directory))
}

pub(super) fn load_or_create(directory: &File, root: &Path) -> std::io::Result<FixtureJournalKey> {
    match load_key(directory, root) {
        Ok(key) => Ok(key),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (key_ref, bytes) = synthetic_key()?;
            store_key(directory, root, key_ref, bytes)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn load_key(directory: &File, root: &Path) -> std::io::Result<FixtureJournalKey> {
    load_key_once(directory, root)
}

fn load_key_once(directory: &File, root: &Path) -> std::io::Result<FixtureJournalKey> {
    let fd = openat(
        directory,
        KEY_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    validate_key_read_stat(&fd, KEY_SIZE)?;
    let mut serialized = [0; KEY_SIZE];
    File::from(fd).read_exact(&mut serialized)?;
    let key_ref = decode_key_ref(&serialized[..48])?;
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&serialized[48..]);
    Ok(FixtureJournalKey {
        bytes,
        key_ref,
        path: root.join(KEY_NAME),
    })
}

pub(super) fn store_key(
    directory: &File,
    root: &Path,
    key_ref: ProviderJournalKeyRef,
    bytes: [u8; 32],
) -> std::io::Result<FixtureJournalKey> {
    let mut record = [0; KEY_SIZE];
    record[..48].copy_from_slice(&encode_key_ref(key_ref));
    record[48..].copy_from_slice(&bytes);
    let temporary = format!(".{KEY_NAME}.{}.tmp", uuid::Uuid::now_v7());
    let fd = openat(
        directory,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(std::io::Error::other)?;
    validate_retained_key_stat(&fd, 0)?;
    let mut file = File::from(fd);
    file.write_all(&record)?;
    file.sync_all()?;
    validate_retained_key_stat(&file, KEY_SIZE)?;
    drop(file);
    renameat(directory, temporary.as_str(), directory, KEY_NAME).map_err(std::io::Error::other)?;
    fsync(directory).map_err(std::io::Error::other)?;
    load_key(directory, root)
}

fn validate_directory(directory: &impl rustix::fd::AsFd) -> std::io::Result<()> {
    let stat = fstat(directory).map_err(std::io::Error::other)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o077 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "fixture runtime root is not owner-private",
        ));
    }
    Ok(())
}

fn validate_key_read_stat(file: &impl rustix::fd::AsFd, size: usize) -> std::io::Result<()> {
    let stat = validated_key_stat(file, size)?;
    if stat.st_nlink > 1 {
        return Err(invalid_key_error());
    }
    Ok(())
}

fn validate_retained_key_stat(file: &impl rustix::fd::AsFd, size: usize) -> std::io::Result<()> {
    let stat = validated_key_stat(file, size)?;
    if stat.st_nlink != 1 {
        return Err(invalid_key_error());
    }
    Ok(())
}

fn validated_key_stat(
    file: &impl rustix::fd::AsFd,
    size: usize,
) -> std::io::Result<rustix::fs::Stat> {
    let stat = fstat(file).map_err(std::io::Error::other)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_size != i64::try_from(size).map_err(std::io::Error::other)?
    {
        return Err(invalid_key_error());
    }
    Ok(stat)
}

fn invalid_key_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "fixture retained key is not owner-private",
    )
}

fn synthetic_key() -> std::io::Result<(ProviderJournalKeyRef, [u8; 32])> {
    let mut bytes = [0; 32];
    let mut key_id = [0; 16];
    let mut authority = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    OsRng.fill_bytes(&mut key_id);
    OsRng.fill_bytes(&mut authority);
    Ok((
        ProviderJournalKeyRef::new(key_id, 1, authority, 1).map_err(std::io::Error::other)?,
        bytes,
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;

    use rustix::fs::{Mode, OFlags, fstat, openat};

    use super::*;

    #[test]
    fn opened_complete_old_inode_is_valid_after_atomic_replacement() {
        let root = tempfile::tempdir().expect("create fixture root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("make fixture root private");
        let directory = open_runtime_root(root.path()).expect("open fixture root");
        let original = load_or_create(&directory, root.path()).expect("create original key");
        let old_fd = openat(
            &directory,
            KEY_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open original key");
        let (replacement_ref, replacement_bytes) = synthetic_key().expect("create replacement");

        store_key(&directory, root.path(), replacement_ref, replacement_bytes)
            .expect("replace key atomically");

        assert_eq!(fstat(&old_fd).expect("stat old key").st_nlink, 0);
        validate_key_read_stat(&old_fd, KEY_SIZE).expect("accept complete unlinked old key");
        let mut serialized = [0; KEY_SIZE];
        File::from(old_fd)
            .read_exact(&mut serialized)
            .expect("read complete old key");
        assert_eq!(&serialized[..48], &encode_key_ref(original.key_ref));
        assert_eq!(&serialized[48..], &original.bytes);
    }
}
