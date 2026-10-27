//! Owns the interval between successful mkdir and validated area publication.
use super::{LinuxManagedAreaRoot, area_name, check_cgroup2, open_area};
use super::super::{LinuxManagedArea, ManagedAreaBinding, ManagedAreaError, ManagedAreaIdentity};
use rustix::fs::{AtFlags, Mode, Stat, fstat, mkdirat, unlinkat};
use std::{fs::File, io::Write, panic::{AssertUnwindSafe, catch_unwind}, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Explicit, Fallback }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Diagnostic {
    phase: Phase,
    initialization: Option<ManagedAreaError>,
    rollback: Result<(), ManagedAreaError>,
}

// Private operation factoring: production always selects Native below.
// Only this module's cfg(test) children may substitute filesystem evidence.
trait Operations {
    fn open(&self, root: &File, name: &str) -> Result<File, ManagedAreaError> {
        open_area(root, name).map(File::from)
    }
    fn stat(&self, file: &File) -> Result<Stat, ManagedAreaError> {
        fstat(file).map_err(|_| ManagedAreaError::Unavailable)
    }
    fn require_empty(&self, file: &File) -> Result<(), ManagedAreaError>;
    fn diagnostic(&self, record: Diagnostic);
}

struct Native;
impl Operations for Native {
    fn require_empty(&self, file: &File) -> Result<(), ManagedAreaError> {
        check_cgroup2(file)?;
        super::super::area::require_empty_directory(file)
    }
    fn diagnostic(&self, record: Diagnostic) {
        // Closed enum fields only. Sink failure must not replace an existing unwind.
        let _ = writeln!(std::io::stderr().lock(), "RUNNE_AREA_CREATION_CLEANUP {record:?}");
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Unarmed, Armed, Published, Removed, Refused, FinalAttempt }

struct Pending<'a> {
    root: &'a File,
    name: String,
    operations: &'a dyn Operations,
    state: State,
    anchor: Option<File>,
    identity: Option<(u64, u64)>,
    initialization: Option<ManagedAreaError>,
}

impl Pending<'_> {
    fn directory(&mut self) -> Result<&File, ManagedAreaError> {
        if self.anchor.is_none() {
            self.anchor = Some(self.operations.open(self.root, &self.name)?);
        }
        let directory = self.anchor.as_ref().ok_or(ManagedAreaError::Unverified)?;
        let stat = self.operations.stat(directory)?;
        let observed = (stat.st_dev, stat.st_ino);
        if self.identity.is_some_and(|identity| identity != observed) {
            self.state = State::Refused;
            return Err(ManagedAreaError::Unverified);
        }
        self.identity = Some(observed);
        Ok(directory)
    }

    fn rollback(&mut self) -> Result<(), ManagedAreaError> {
        let operations = self.operations;
        let identity = {
            let directory = self.directory()?;
            operations.require_empty(directory)?;
            let stat = operations.stat(directory)?;
            (stat.st_dev, stat.st_ino)
        };
        let current = operations.open(self.root, &self.name)?;
        let stat = operations.stat(&current)?;
        if (stat.st_dev, stat.st_ino) != identity || self.identity != Some(identity) {
            self.state = State::Refused;
            return Err(ManagedAreaError::Unverified);
        }
        // The final compare/unlink interval requires the documented exclusive writer.
        unlinkat(self.root, self.name.as_str(), AtFlags::REMOVEDIR)
            .map_err(|_| ManagedAreaError::Unverified)?;
        self.state = State::Removed; // Retire immediately; no fallible work before this.
        Ok(())
    }

    fn report(&self, phase: Phase, rollback: Result<(), ManagedAreaError>) {
        let record = Diagnostic { phase, initialization: self.initialization, rollback };
        let _ = catch_unwind(AssertUnwindSafe(|| self.operations.diagnostic(record)));
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if self.state != State::Armed { return; }
        // At most one fallback; never retry a known replacement/refused identity.
        self.state = State::FinalAttempt;
        let result = catch_unwind(AssertUnwindSafe(|| self.rollback()))
            .unwrap_or(Err(ManagedAreaError::Unverified));
        self.report(Phase::Fallback, result);
    }
}

fn create_using<T>(
    root: &File,
    name: String,
    operations: &dyn Operations,
    initialize: impl FnOnce(&mut Pending<'_>) -> Result<T, ManagedAreaError>,
) -> Result<T, ManagedAreaError> {
    // All guard storage exists before mkdir; arming after success is infallible.
    let mut pending = Pending {
        root, name, operations, state: State::Unarmed,
        anchor: None, identity: None, initialization: None,
    };
    mkdirat(root, pending.name.as_str(), Mode::from_raw_mode(0o700)).map_err(|error| {
        if error == rustix::io::Errno::EXIST { ManagedAreaError::Conflict }
        else { ManagedAreaError::Unavailable }
    })?;
    pending.state = State::Armed;
    match initialize(&mut pending) {
        Ok(area) => {
            pending.state = State::Published;
            Ok(area)
        }
        Err(initialization) => {
            pending.initialization = Some(initialization);
            match pending.rollback() {
                Ok(()) => Err(initialization),
                Err(rollback) => {
                    pending.report(Phase::Explicit, Err(rollback));
                    // Both closed causes survive diagnostically, not in this return enum.
                    Err(ManagedAreaError::Unverified)
                }
            }
        }
    }
}

pub(super) fn create(
    root: &LinuxManagedAreaRoot, binding: ManagedAreaBinding,
) -> Result<LinuxManagedArea, ManagedAreaError> {
    let name = area_name(binding);
    create_using(root.directory.as_ref(), name, &Native, |pending| {
        let directory = pending.directory()?.try_clone()
            .map_err(|_| ManagedAreaError::Unavailable)?;
        let metadata = fstat(&directory).map_err(|_| ManagedAreaError::Unavailable)?;
        check_cgroup2(&directory)?;
        let identity = ManagedAreaIdentity::new(
            root.boot_id, root.device, root.inode,
            metadata.st_dev, metadata.st_ino, binding,
        )?;
        let area = LinuxManagedArea::new(
            Arc::clone(&root.directory), directory, pending.name.clone(), identity,
        );
        area.require_empty()?;
        Ok(area)
    })
}

#[cfg(test)]
#[path = "creation/tests.rs"]
mod tests;
