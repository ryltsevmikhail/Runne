//! Canonical protected-file persistence for the fixture-only publication effect ledger.
#![allow(clippy::missing_errors_doc, clippy::redundant_pub_crate, dead_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::Digest;
use crate::publication_effect_ledger::FixturePublicationEffectLedger;
use crate::publication_effect_types::{
    PublicationEffectError, PublicationEffectScope, PublicationEffectState,
};

#[path = "publication_effect_durable_codec.rs"]
mod codec;
pub(crate) use codec::{decode_ledger, encode_ledger};

const SCHEMA: &str = "runne.release.publication-effect-ledger/1";

/// File-backed fixture publication-effect ledger. Mutations persist before returning.
pub(crate) struct DurableFixturePublicationEffectLedger {
    pub(crate) path: PathBuf,
    _lease: crate::store_durable_lease::Lease,
    pub(crate) ledger: FixturePublicationEffectLedger,
    poisoned: bool,
    #[cfg(test)]
    failpoint: Option<crate::publication_effect_failpoint::PublicationEffectFailpoint>,
}

impl DurableFixturePublicationEffectLedger {
    pub(crate) fn create(path: impl AsRef<Path>) -> Result<Self, PublicationEffectError> {
        let lease = crate::store_durable_lease::Lease::acquire(path.as_ref())
            .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
        let this = Self {
            path: path.as_ref().into(),
            _lease: lease,
            ledger: FixturePublicationEffectLedger::default(),
            poisoned: false,
            #[cfg(test)]
            failpoint: None,
        };
        this.save_new()?;
        Ok(this)
    }

    pub(crate) fn reopen(path: impl AsRef<Path>) -> Result<Self, PublicationEffectError> {
        let lease = crate::store_durable_lease::Lease::acquire(path.as_ref())
            .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
        let mut bytes = Vec::new();
        safe_open(path.as_ref())?
            .read_to_end(&mut bytes)
            .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
        Ok(Self {
            path: path.as_ref().into(),
            _lease: lease,
            ledger: decode_ledger(&bytes)?,
            poisoned: false,
            #[cfg(test)]
            failpoint: None,
        })
    }

    pub(crate) fn recover(
        &self,
        scope: &PublicationEffectScope,
    ) -> Result<crate::publication_effect_types::PublicationEffectRecovery, PublicationEffectError>
    {
        if self.poisoned {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        self.ledger.recover(scope)
    }

    pub(crate) fn state(&self, namespace: &str) -> Option<PublicationEffectState> {
        self.ledger.state(namespace)
    }

    pub(crate) fn settlement(&self, namespace: &str) -> Option<Digest> {
        self.ledger.settlement(namespace)
    }

    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn save_new(&self) -> Result<(), PublicationEffectError> {
        let bytes = encode_ledger(&self.ledger)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(no_follow());
        }
        let mut file = options
            .open(&self.path)
            .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
        crate::store_durable_file::safe_file(&self.path)
            .and_then(|()| crate::store_durable_file::sync_parent(&self.path))
            .map_err(|_| PublicationEffectError::DurableStateUnavailable)
    }

    pub(crate) fn save(
        &mut self,
        ledger: &FixturePublicationEffectLedger,
    ) -> Result<(), PublicationEffectError> {
        if self.poisoned {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        let bytes = encode_ledger(ledger)?;
        crate::store_durable_file::safe_file(&self.path)
            .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
        let temp = crate::store_durable_file::temp_file(&self.path, &bytes)
            .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
        fs::rename(temp, &self.path)
            .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
        #[cfg(test)]
        if self.take_failpoint(
            crate::publication_effect_failpoint::PublicationEffectFailpoint::AfterRenameBeforeParentSync,
        ) {
            self.poisoned = true;
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        let committed = crate::store_durable_file::safe_file(&self.path)
            .and_then(|()| crate::store_durable_file::sync_parent(&self.path))
            .map_err(|_| PublicationEffectError::DurableStateUnavailable);
        if committed.is_err() {
            self.poisoned = true;
        }
        committed
    }

    #[cfg(test)]
    pub(crate) const fn arm_failpoint(
        &mut self,
        failpoint: crate::publication_effect_failpoint::PublicationEffectFailpoint,
    ) {
        self.failpoint = Some(failpoint);
    }

    #[cfg(test)]
    pub(crate) fn take_failpoint(
        &mut self,
        failpoint: crate::publication_effect_failpoint::PublicationEffectFailpoint,
    ) -> bool {
        if self.failpoint == Some(failpoint) {
            self.failpoint = None;
            true
        } else {
            false
        }
    }
}

fn safe_open(path: &Path) -> Result<File, PublicationEffectError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(no_follow());
    }
    let file = options
        .open(path)
        .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
    }
    #[cfg(not(unix))]
    return Err(PublicationEffectError::DurableStateUnavailable);
    Ok(file)
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
