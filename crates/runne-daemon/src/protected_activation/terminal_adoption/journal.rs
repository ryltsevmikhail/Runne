//! Durable non-secret transition witness; no provider grants or credentials.
use super::{DaemonError, Path, failure};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const NAME: &str = ".terminal-protected-adoption-v1.json";
const LIMIT: u64 = 4096;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    version: u8,
    manifest: String,
    authority: [u8; 16],
    local_authority: [u8; 16],
    lineage: [u8; 16],
    pub(super) generation: u64,
}

pub(super) fn load_or_create(
    root: &Path,
    manifest: &str,
    authority: [u8; 16],
    local_authority: [u8; 16],
    lineage: [u8; 16],
    generation: u64,
) -> Result<Pending, DaemonError> {
    let expected = Pending {
        version: 1,
        manifest: manifest.to_owned(),
        authority,
        local_authority,
        lineage,
        generation,
    };
    let path = root.join(NAME);
    if path.symlink_metadata().is_ok() {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| failure("adoption witness unavailable"))?;
        let meta = file
            .metadata()
            .map_err(|_| failure("adoption witness unavailable"))?;
        if !meta.is_file()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
            || meta.len() > LIMIT
        {
            return Err(failure("adoption witness is not owner-private"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure("adoption witness unreadable"))?;
        let pending: Pending =
            serde_json::from_slice(&bytes).map_err(|_| failure("adoption witness invalid"))?;
        let mut normalized = pending;
        let retained_generation = normalized.generation;
        normalized.generation = generation;
        if normalized != expected || retained_generation == 0 || retained_generation > generation {
            return Err(failure("adoption witness conflicts with this installation"));
        }
        normalized.generation = retained_generation;
        return Ok(normalized);
    }
    let bytes = serde_json::to_vec(&expected).map_err(|_| failure("adoption witness invalid"))?;
    let temporary = root.join(format!(".terminal-adoption-{}.tmp", uuid::Uuid::now_v7()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| failure("adoption witness publication unavailable"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| failure("adoption witness publication uncertain"))?;
    std::fs::hard_link(&temporary, &path)
        .map_err(|_| failure("adoption witness publication conflict"))?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| failure("adoption witness directory sync uncertain"))?;
    std::fs::remove_file(temporary).map_err(|_| failure("adoption witness cleanup unavailable"))?;
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_preserves_original_generation_and_rejects_changed_consent() {
        let directory = tempfile::tempdir().unwrap();
        let first =
            load_or_create(directory.path(), "manifest", [1; 16], [2; 16], [3; 16], 7).unwrap();
        let retry =
            load_or_create(directory.path(), "manifest", [1; 16], [2; 16], [3; 16], 8).unwrap();
        assert_eq!(first, retry);
        assert!(load_or_create(directory.path(), "other", [1; 16], [2; 16], [3; 16], 9).is_err());
        assert!(
            load_or_create(directory.path(), "manifest", [4; 16], [2; 16], [3; 16], 9).is_err()
        );
        assert!(
            load_or_create(directory.path(), "manifest", [1; 16], [2; 16], [3; 16], 6).is_err()
        );
    }

    #[test]
    fn symlink_witness_cannot_be_adopted() {
        let directory = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/null", directory.path().join(NAME)).unwrap();
        assert!(
            load_or_create(directory.path(), "manifest", [1; 16], [2; 16], [3; 16], 7).is_err()
        );
    }
}
