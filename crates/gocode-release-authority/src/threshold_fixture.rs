//! File-backed, single-writer threshold context for fixture and reference recovery tests.

use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::threshold_fixture_wire::{
    Acknowledgement, FileState, JournalEntry, canonical_id, decode, encode, hex,
};
use crate::{
    AuthenticatedThresholdTransition, AuthorityError, Digest, ThresholdAckProof,
    ThresholdAckRequest, ThresholdAdmission, ThresholdAdmissionRequest,
    ThresholdVerificationContext, ThresholdVerificationState,
};

/// Immutable domain binding which prevents opening a threshold file for another bootstrap/profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdFixtureStoreBinding {
    pub(crate) bootstrap: Digest,
    pub(crate) profile: String,
    pub(crate) version: u64,
}
impl ThresholdFixtureStoreBinding {
    /// Construct a canonical fixture binding.
    ///
    /// # Errors
    /// Returns an error for a non-canonical profile identifier.
    pub fn new(bootstrap: Digest, profile: &str, version: u64) -> Result<Self, AuthorityError> {
        canonical_id(profile)
            .then(|| Self {
                bootstrap,
                profile: profile.into(),
                version,
            })
            .ok_or(AuthorityError::NonCanonicalPayload)
    }
}

/// A durable, fail-closed reference context.  It deliberately supports one writer only.
pub struct DurableFixtureThresholdContext {
    path: PathBuf,
    binding: ThresholdFixtureStoreBinding,
    _lease: crate::store_durable_lease::Lease,
    lock: RefCell<()>,
}
impl DurableFixtureThresholdContext {
    /// Create a new canonical state file without replacing an existing object.
    ///
    /// # Errors
    /// Returns an error when the path is unsafe, exists, or cannot be durably initialized.
    pub fn create(
        path: impl AsRef<Path>,
        binding: ThresholdFixtureStoreBinding,
        state: ThresholdVerificationState,
        now: u64,
    ) -> Result<Self, AuthorityError> {
        let this = Self {
            path: path.as_ref().into(),
            binding,
            _lease: crate::store_durable_lease::Lease::acquire(path.as_ref())?,
            lock: RefCell::new(()),
        };
        this.create_file(&FileState {
            state,
            now,
            journal: Vec::new(),
            acknowledgements: Vec::new(),
        })?;
        Ok(this)
    }
    /// Reopen an exact canonical file tied to the supplied immutable store binding.
    ///
    /// # Errors
    /// Returns an error when the file is unsafe, corrupt, or bound to another store.
    pub fn reopen(
        path: impl AsRef<Path>,
        binding: ThresholdFixtureStoreBinding,
    ) -> Result<Self, AuthorityError> {
        let this = Self {
            path: path.as_ref().into(),
            binding,
            _lease: crate::store_durable_lease::Lease::acquire(path.as_ref())?,
            lock: RefCell::new(()),
        };
        this.load().map(|_| this)
    }
    /// Read the current trusted persisted threshold state.
    ///
    /// # Errors
    /// Returns an error when the state file is unavailable or non-canonical.
    pub fn state(&self) -> Result<ThresholdVerificationState, AuthorityError> {
        self.load().map(|file| file.state)
    }
    fn load(&self) -> Result<FileState, AuthorityError> {
        safe_file(&self.path)?;
        let mut bytes = Vec::new();
        File::open(&self.path)
            .map_err(|_| AuthorityError::DurableStateUnavailable)?
            .read_to_end(&mut bytes)
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        let file = decode(&bytes, &self.binding)?;
        (encode(&file, &self.binding) == bytes)
            .then_some(file)
            .ok_or(AuthorityError::NonCanonicalPayload)
    }
    fn create_file(&self, file: &FileState) -> Result<(), AuthorityError> {
        let bytes = encode(file, &self.binding);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&self.path)
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        output
            .write_all(&bytes)
            .and_then(|()| output.sync_all())
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        safe_file(&self.path)?;
        sync_parent(&self.path)
    }
    fn replace(&self, file: &FileState) -> Result<(), AuthorityError> {
        safe_file(&self.path)?;
        let bytes = encode(file, &self.binding);
        let temp = temp_file(&self.path, &bytes)?;
        fs::rename(temp, &self.path).map_err(|_| AuthorityError::DurableStateUnavailable)?;
        safe_file(&self.path)?;
        sync_parent(&self.path)
    }
}
impl ThresholdVerificationContext for DurableFixtureThresholdContext {
    fn recover_existing(
        &self,
        request: &ThresholdAdmissionRequest<'_>,
    ) -> Result<Option<ThresholdAdmission>, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        self.load()?
            .journal
            .iter()
            .find(|entry| same_key(&entry.scope, &request.scope()))
            .map_or(Ok(None), |entry| {
                (entry.scope == request.scope())
                    .then_some(ThresholdAdmission::ExistingSame {
                        admission_id: entry.admission,
                    })
                    .map(Some)
                    .ok_or(AuthorityError::BindingMismatch)
            })
    }
    fn trusted_state_and_now(&self) -> Result<(ThresholdVerificationState, u64), AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let file = self.load()?;
        Ok((file.state, file.now))
    }
    fn persist_new(
        &self,
        transition: AuthenticatedThresholdTransition,
    ) -> Result<ThresholdAdmission, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut file = self.load()?;
        if let Some(entry) = file
            .journal
            .iter()
            .find(|entry| same_key(&entry.scope, transition.scope()))
        {
            return (entry.scope == *transition.scope()
                && entry.admission == transition.admission_id()
                && entry.next == *transition.next_state())
            .then_some(ThresholdAdmission::ExistingSame {
                admission_id: entry.admission,
            })
            .ok_or(AuthorityError::BindingMismatch);
        }
        if file.state.generation != transition.expected_generation() {
            return Err(AuthorityError::BindingMismatch);
        }
        let admission = transition.admission_id();
        file.state = transition.next_state().clone();
        file.journal.push(JournalEntry {
            scope: transition.scope().clone(),
            admission,
            next: file.state.clone(),
        });
        self.replace(&file)?;
        Ok(ThresholdAdmission::NewlyAdmitted {
            admission_id: admission,
        })
    }
    fn acknowledge_or_recover(
        &self,
        request: &ThresholdAckRequest<'_>,
    ) -> Result<ThresholdAckProof, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut file = self.load()?;
        let admission = request.admission();
        let revision = request.revision();
        let admitted = file.journal.iter().any(|entry| {
            entry.admission == admission && entry.scope.revision.checked_add(1) == Some(revision)
        });
        if !admitted {
            return Err(AuthorityError::BindingMismatch);
        }
        if !file
            .acknowledgements
            .iter()
            .any(|ack| ack.admission == admission && ack.revision == revision)
        {
            if file
                .acknowledgements
                .iter()
                .any(|ack| ack.admission == admission)
            {
                return Err(AuthorityError::BindingMismatch);
            }
            file.acknowledgements.push(Acknowledgement {
                admission,
                revision,
            });
            self.replace(&file)?;
        }
        Ok(request.acknowledge())
    }
}
fn same_key(left: &crate::ThresholdAdmissionScope, right: &crate::ThresholdAdmissionScope) -> bool {
    left.authority_instance == right.authority_instance
        && left.promotion == right.promotion
        && left.revision == right.revision
        && left.command == right.command
}

fn temp_file(path: &Path, bytes: &[u8]) -> Result<PathBuf, AuthorityError> {
    let parent = path
        .parent()
        .ok_or(AuthorityError::DurableStateUnavailable)?;
    let name = path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or(AuthorityError::DurableStateUnavailable)?;
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .map_err(|_| AuthorityError::DurableStateUnavailable)?
        .read_exact(&mut random)
        .map_err(|_| AuthorityError::DurableStateUnavailable)?;
    let temp = parent.join(format!(".{name}.{}.tmp", hex(&random)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(&temp)
        .map_err(|_| AuthorityError::DurableStateUnavailable)?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|_| AuthorityError::DurableStateUnavailable)?;
    Ok(temp)
}
fn safe_file(path: &Path) -> Result<(), AuthorityError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AuthorityError::DurableStateUnavailable)?;
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
    #[cfg(not(unix))]
    {
        return Err(AuthorityError::DurableStateUnavailable);
    }
    Ok(())
}
fn sync_parent(path: &Path) -> Result<(), AuthorityError> {
    File::open(
        path.parent()
            .ok_or(AuthorityError::DurableStateUnavailable)?,
    )
    .and_then(|file| file.sync_all())
    .map_err(|_| AuthorityError::DurableStateUnavailable)
}

#[cfg(test)]
#[path = "threshold_fixture_key_tests.rs"]
mod key_tests;
