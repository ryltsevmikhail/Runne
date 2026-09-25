use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
};

const CONTENT: &[u8] = b"RUNNE-LINUX-SIGNED-V3-ACTIVE-V1\n";

pub(super) fn state_path(runtime_root: &Path) -> std::io::Result<PathBuf> {
    let profile = runtime_root.parent().ok_or_else(invalid_data)?;
    let profile_metadata = fs::symlink_metadata(profile)?;
    let current_uid = fs::metadata("/proc/self")?.uid();
    if !profile_metadata.is_dir()
        || profile_metadata.file_type().is_symlink()
        || profile_metadata.uid() != current_uid
        || profile_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(invalid_data());
    }
    let state_directory = profile.join(".runne-native-enrollment");
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(&state_directory) {
        Ok(()) => {
            // mkdir's requested mode is already private even under umask 0000;
            // set the exact owner mode before syncing the new directory entry.
            fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))?;
            File::open(&state_directory)?.sync_all()?;
            File::open(profile)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    private_parent(&state_directory)?;
    Ok(state_directory.join("signed-linux-v3-active.state"))
}

pub(super) fn load(path: &Path) -> std::io::Result<bool> {
    let parent = path.parent().ok_or_else(invalid_data)?;
    let parent_metadata = private_parent(parent)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != parent_metadata.uid()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(invalid_data());
    }
    let mut file = File::open(path)?;
    let identity = file.metadata()?;
    let mut bytes = Vec::with_capacity(CONTENT.len() + 1);
    file.read_to_end(&mut bytes)?;
    if file.metadata()?.ino() != identity.ino()
        || file.metadata()?.dev() != identity.dev()
        || fs::symlink_metadata(path)?.ino() != identity.ino()
        || bytes != CONTENT
    {
        return Err(invalid_data());
    }
    Ok(true)
}

pub(super) fn persist(path: &Path) -> std::io::Result<()> {
    if load(path)? {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(invalid_data)?;
    let temporary = parent.join(format!(".signed-linux-v3-{}.tmp", uuid::Uuid::now_v7()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(CONTENT)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !load(path)? {
                    return Err(invalid_data());
                }
                fs::remove_file(&temporary)?;
                File::open(parent)?.sync_all()?;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        File::open(parent)?.sync_all()?;
        if !load(path)? {
            return Err(invalid_data());
        }
        fs::remove_file(&temporary)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(super) fn persist_before_transition<T, E>(
    path: &Path,
    transition: impl FnOnce() -> Result<T, E>,
    map_persist_error: impl FnOnce(std::io::Error) -> E,
) -> Result<T, E> {
    persist(path).map_err(map_persist_error)?;
    transition()
}

fn invalid_data() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid Linux V3 latch")
}

fn private_parent(path: &Path) -> std::io::Result<std::fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    let current_uid = fs::metadata("/proc/self")?.uid();
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid_data());
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_observes_durable_latch_and_is_skipped_if_persistence_fails() {
        let temporary = tempfile::tempdir().expect("private test profile");
        let runtime = temporary.path().join("bundled-runtime");
        fs::create_dir(&runtime).expect("runtime root");
        let path = state_path(&runtime).expect("latch path");
        let observed = persist_before_transition(
            &path,
            || {
                assert!(load(&path).expect("read persisted latch"));
                Ok::<_, ()>(true)
            },
            |_| (),
        );
        assert_eq!(observed, Ok(true));

        let bad_profile = temporary.path().join("writable-profile");
        fs::create_dir(&bad_profile).expect("unsafe profile");
        fs::set_permissions(&bad_profile, fs::Permissions::from_mode(0o777))
            .expect("make unsafe profile writable");
        let bad_runtime = bad_profile.join("bundled-runtime");
        fs::create_dir(&bad_runtime).expect("unsafe runtime root");
        assert!(state_path(&bad_runtime).is_err());
        let bad_path = bad_profile.join(".runne-native-enrollment/state");
        let invoked = std::cell::Cell::new(false);
        let rejected = persist_before_transition(
            &bad_path,
            || {
                invoked.set(true);
                Ok::<_, std::io::Error>(())
            },
            std::convert::identity,
        );
        assert!(rejected.is_err());
        assert!(!invoked.get());
    }

    #[test]
    fn latch_directory_is_created_with_owner_only_permissions() {
        let temporary = tempfile::tempdir().expect("private test profile");
        let runtime = temporary.path().join("bundled-runtime");
        fs::create_dir(&runtime).expect("runtime root");
        let path = state_path(&runtime).expect("latch path");
        let metadata = fs::symlink_metadata(path.parent().expect("latch directory"))
            .expect("latch directory metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }
}
