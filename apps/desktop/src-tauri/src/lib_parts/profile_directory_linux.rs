use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
};

fn ensure_linux_profile_directory_private(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let current_uid = fs::metadata("/proc/self")?.uid();
    // Linux O_DIRECTORY | O_NOFOLLOW pins the final directory entry without
    // following a replacement symlink. File methods below operate on this fd.
    let directory = open_profile_directory(path)?;
    secure_opened_profile_directory(path, &directory, current_uid)
}

fn secure_opened_profile_directory(
    path: &Path,
    directory: &File,
    current_uid: u32,
) -> std::io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != current_uid {
        return Err(invalid_profile_directory());
    }

    directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    let secured = fs::symlink_metadata(path)?;
    if secured.file_type().is_symlink()
        || !secured.is_dir()
        || secured.uid() != current_uid
        || secured.dev() != metadata.dev()
        || secured.ino() != metadata.ino()
        || secured.permissions().mode() & 0o777 != 0o700
    {
        return Err(invalid_profile_directory());
    }
    Ok(())
}

fn open_profile_directory(path: &Path) -> std::io::Result<File> {
    // Linux ABI flags: O_DIRECTORY = 0o200_000, O_NOFOLLOW = 0o400_000.
    OpenOptions::new()
        .read(true)
        .custom_flags(0o200_000 | 0o400_000)
        .open(path)
}

fn invalid_profile_directory() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "unsafe Linux profile directory",
    )
}

#[cfg(test)]
mod profile_directory_linux_tests {
    use super::*;

    #[test]
    fn secures_existing_permissive_directory_and_rejects_symlink() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let profile = temporary.path().join("profile");
        fs::create_dir(&profile).expect("create profile");
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o777))
            .expect("make profile permissive");

        ensure_linux_profile_directory_private(&profile).expect("secure profile");
        assert_eq!(
            fs::symlink_metadata(&profile)
                .expect("profile metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let target = temporary.path().join("target");
        fs::create_dir(&target).expect("create target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .expect("make symlink target readable");
        let link = temporary.path().join("linked-profile");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        let result = ensure_linux_profile_directory_private(&link)
            .and_then(|()| fs::create_dir_all(link.join("local-engine").join("models")));
        assert!(result.is_err());
        assert!(!target.join("local-engine").exists());
        assert_eq!(
            fs::symlink_metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[test]
    fn replacement_after_open_never_changes_symlink_target_permissions() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let profile = temporary.path().join("profile");
        let detached = temporary.path().join("detached-profile");
        let target = temporary.path().join("target");
        fs::create_dir(&profile).expect("create profile");
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o777))
            .expect("make profile permissive");
        fs::create_dir(&target).expect("create target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .expect("make target readable");

        let directory = open_profile_directory(&profile).expect("open profile without following");
        fs::rename(&profile, &detached).expect("detach opened directory");
        std::os::unix::fs::symlink(&target, &profile).expect("replace profile with symlink");
        let current_uid = fs::metadata("/proc/self").expect("process metadata").uid();

        assert!(secure_opened_profile_directory(&profile, &directory, current_uid).is_err());
        assert_eq!(
            fs::symlink_metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::symlink_metadata(&detached)
                .expect("detached metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
