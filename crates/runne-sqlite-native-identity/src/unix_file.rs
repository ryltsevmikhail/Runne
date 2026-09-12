use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use crate::{DatabaseFileIdentity, IdentityError};

/// Measures a single-linked regular file at the supplied path.
///
/// # Errors
/// Rejects missing, nonregular, multiply-linked or invalid file identities.
pub fn path_database_identity(path: &Path) -> Result<DatabaseFileIdentity, IdentityError> {
    identity(&std::fs::metadata(path).map_err(|_| IdentityError)?)
}

/// Measures the retained file descriptor without reopening a pathname.
///
/// This can bind an exclusive-create witness to `SQLite`'s independently measured
/// main-file handle. It does not prove ownership, permissions or `SQLite` validity.
///
/// # Errors
/// Rejects nonregular, unlinked, multiply-linked or invalid file identities.
pub fn file_database_identity(file: &File) -> Result<DatabaseFileIdentity, IdentityError> {
    identity(&file.metadata().map_err(|_| IdentityError)?)
}

fn identity(meta: &Metadata) -> Result<DatabaseFileIdentity, IdentityError> {
    if !meta.file_type().is_file() || meta.nlink() != 1 || meta.dev() == 0 || meta.ino() == 0 {
        return Err(IdentityError);
    }
    Ok(DatabaseFileIdentity {
        device: meta.dev(),
        inode: meta.ino(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_identity_survives_rename_and_rejects_aliases() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sqlite-fd-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&root).expect("own temporary directory");
        let path = root.join("database");
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let captured = file_database_identity(&file).expect("retained file identity");
        assert_eq!(path_database_identity(&path), Ok(captured));
        let retained = root.join("retained");
        std::fs::rename(&path, &retained).unwrap();
        let replacement = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        assert_eq!(file_database_identity(&file), Ok(captured));
        assert_ne!(file_database_identity(&replacement), Ok(captured));
        assert_ne!(path_database_identity(&path), Ok(captured));
        assert_eq!(
            file_database_identity(&File::open(&root).unwrap()),
            Err(IdentityError)
        );
        let alias = root.join("alias");
        std::fs::hard_link(&retained, &alias).unwrap();
        assert_eq!(file_database_identity(&file), Err(IdentityError));
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_file(retained).unwrap();
        assert_eq!(file_database_identity(&file), Err(IdentityError));
        drop((file, replacement));
        std::fs::remove_dir_all(root).unwrap();
    }
}
