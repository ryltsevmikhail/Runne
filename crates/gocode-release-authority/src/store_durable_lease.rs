//! OS-backed exclusive lease for a fixture durable store path.

use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::{AuthorityError, Digest};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityAnchor {
    pub authority_instance: Digest,
    pub generation: u64,
    pub authority_file: Digest,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AnchorWire {
    schema_version: String,
    authority_instance_sha256: String,
    generation: u64,
    authority_file_sha256: String,
}

pub struct Lease {
    _path: PathBuf,
    file: File,
}
impl Lease {
    pub fn acquire(store: &Path) -> Result<Self, AuthorityError> {
        let path = store.with_extension(
            store
                .extension()
                .and_then(|value| value.to_str())
                .map_or_else(|| "lease".into(), |value| format!("{value}.lease")),
        );
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(no_follow());
        }
        let file = options
            .open(&path)
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        safe(&file)?;
        file.try_lock_exclusive()
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        Ok(Self { _path: path, file })
    }

    pub(crate) fn initialize_authority_anchor(
        &self,
        anchor: AuthorityAnchor,
    ) -> Result<(), AuthorityError> {
        (self.file.metadata().map_err(unavailable)?.len() == 0)
            .then_some(())
            .ok_or(AuthorityError::DurableStateUnavailable)?;
        self.write_anchor(anchor)
    }

    pub(crate) fn authority_anchor(&self) -> Result<AuthorityAnchor, AuthorityError> {
        let mut file = self.file.try_clone().map_err(unavailable)?;
        file.seek(SeekFrom::Start(0)).map_err(unavailable)?;
        let mut bytes = Vec::new();
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        if bytes.len() > 4096 {
            return Err(AuthorityError::DurableStateUnavailable);
        }
        let wire: AnchorWire =
            serde_json::from_slice(&bytes).map_err(|_| AuthorityError::DurableStateUnavailable)?;
        if encode_anchor(&wire)? != bytes
            || wire.schema_version != "gocode.release.durable-authority-anchor/1"
            || wire.generation == 0
        {
            return Err(AuthorityError::DurableStateUnavailable);
        }
        Ok(AuthorityAnchor {
            authority_instance: digest(&wire.authority_instance_sha256)?,
            generation: wire.generation,
            authority_file: digest(&wire.authority_file_sha256)?,
        })
    }

    pub(crate) fn update_authority_anchor(
        &self,
        expected: AuthorityAnchor,
        next: AuthorityAnchor,
    ) -> Result<(), AuthorityError> {
        (self.authority_anchor()? == expected
            && next.authority_instance == expected.authority_instance
            && next.generation
                == expected
                    .generation
                    .checked_add(1)
                    .ok_or(AuthorityError::DurableStateUnavailable)?)
        .then_some(())
        .ok_or(AuthorityError::DurableStateUnavailable)?;
        self.write_anchor(next)
    }

    fn write_anchor(&self, anchor: AuthorityAnchor) -> Result<(), AuthorityError> {
        let bytes = encode_anchor(&AnchorWire {
            schema_version: "gocode.release.durable-authority-anchor/1".into(),
            authority_instance_sha256: anchor.authority_instance.to_hex(),
            generation: anchor.generation,
            authority_file_sha256: anchor.authority_file.to_hex(),
        })?;
        let mut file = self.file.try_clone().map_err(unavailable)?;
        file.seek(SeekFrom::Start(0)).map_err(unavailable)?;
        file.set_len(0).map_err(unavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(unavailable)
    }
}

fn encode_anchor(wire: &AnchorWire) -> Result<Vec<u8>, AuthorityError> {
    let mut bytes =
        serde_json::to_vec(wire).map_err(|_| AuthorityError::DurableStateUnavailable)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn digest(value: &str) -> Result<Digest, AuthorityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(AuthorityError::DurableStateUnavailable);
    }
    let mut bytes = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| AuthorityError::DurableStateUnavailable)?,
            16,
        )
        .map_err(|_| AuthorityError::DurableStateUnavailable)?;
    }
    Ok(Digest::from_bytes(bytes))
}

fn unavailable(_: std::io::Error) -> AuthorityError {
    AuthorityError::DurableStateUnavailable
}
fn safe(file: &File) -> Result<(), AuthorityError> {
    let metadata = file
        .metadata()
        .map_err(|_| AuthorityError::DurableStateUnavailable)?;
    if !metadata.file_type().is_file() {
        return Err(AuthorityError::DurableStateUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(AuthorityError::DurableStateUnavailable);
        }
    }
    Ok(())
}
#[cfg(target_os = "macos")]
const fn no_follow() -> i32 {
    0x0100
}
#[cfg(all(target_os = "linux", not(target_os = "macos")))]
const fn no_follow() -> i32 {
    0o400_000
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const fn no_follow() -> i32 {
    0
}
