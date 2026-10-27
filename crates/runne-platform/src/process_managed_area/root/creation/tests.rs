//! Guest-only ordinary-RAM lifecycle faults, never cgroup/kernel qualification.
use super::*;
use std::{cell::{Cell, RefCell}, path::PathBuf};

#[derive(Default)]
struct Policy {
    fail_open_once: Cell<bool>,
    fail_stat_once: Cell<bool>,
    checks: Cell<usize>,
    panic_diagnostic: bool,
    check: Option<Box<dyn Fn(&File) -> Result<(), ManagedAreaError>>>,
    records: RefCell<Vec<Diagnostic>>,
}
impl Operations for Policy {
    fn open(&self, root: &File, name: &str) -> Result<File, ManagedAreaError> {
        if self.fail_open_once.replace(false) { return Err(ManagedAreaError::Unavailable); }
        open_area(root, name).map(File::from)
    }
    fn stat(&self, file: &File) -> Result<Stat, ManagedAreaError> {
        if self.fail_stat_once.replace(false) { return Err(ManagedAreaError::Unavailable); }
        fstat(file).map_err(|_| ManagedAreaError::Unavailable)
    }
    fn require_empty(&self, file: &File) -> Result<(), ManagedAreaError> {
        self.checks.set(self.checks.get() + 1);
        match &self.check { Some(check) => check(file), None => Ok(()) }
    }
    fn diagnostic(&self, record: Diagnostic) {
        self.records.borrow_mut().push(record);
        if self.panic_diagnostic { panic!("injected diagnostic sink failure"); }
    }
}

struct Fixture { root: tempfile::TempDir, parent: File }
impl Fixture {
    fn new() -> Self {
        // Selected execution belongs only in separately reviewed disposable guest.
        let root = tempfile::Builder::new().prefix("area-create-fault-")
            .tempdir_in("/dev/shm").unwrap();
        let parent = File::open(root.path()).unwrap();
        Self { root, parent }
    }
    fn path(&self) -> PathBuf { self.root.path().join("owned") }
    fn fail(&self, policy: &Policy, pin: bool) -> Result<(), ManagedAreaError> {
        create_using(&self.parent, "owned".into(), policy, |pending| {
            if pin { pending.directory()?; }
            Err(ManagedAreaError::Unavailable)
        })
    }
    fn finish(self) {
        let Self { root, parent } = self;
        drop(parent);
        root.close().expect("fallible owned RAM fixture disposal");
    }
}

fn early_and_pinned_failures() {
    for phase in 0..4 {
        let f = Fixture::new();
        let policy = Policy::default();
        policy.fail_open_once.set(phase == 1);
        policy.fail_stat_once.set(phase == 2);
        assert_eq!(f.fail(&policy, phase != 0), Err(ManagedAreaError::Unavailable));
        assert!(!f.path().exists(), "mkdir result must be owned before first open/stat");
        assert_eq!(policy.checks.get(), 1, "successful rollback must retire before Drop");
        assert!(policy.records.borrow().is_empty());
        f.finish();
    }
}

fn conflict_and_publication() {
    let f = Fixture::new();
    std::fs::create_dir(f.path()).unwrap();
    std::fs::write(f.path().join("sentinel"), b"existing").unwrap();
    let policy = Policy::default();
    assert_eq!(f.fail(&policy, false), Err(ManagedAreaError::Conflict));
    assert_eq!(std::fs::read(f.path().join("sentinel")).unwrap(), b"existing");
    assert_eq!(policy.checks.get(), 0);
    assert!(policy.records.borrow().is_empty());
    f.finish();
    let f = Fixture::new();
    let policy = Policy::default();
    let result = create_using(&f.parent, "owned".into(), &policy, |pending| {
        pending.directory()?;
        Ok(17)
    });
    assert_eq!(result, Ok(17));
    assert!(f.path().is_dir(), "publication hands ownership to caller");
    assert_eq!(policy.checks.get(), 0);
    assert!(policy.records.borrow().is_empty());
    f.finish();
}

fn replacement_and_symlink() {
    for symlink in [false, true] {
        let f = Fixture::new();
        let path = f.path();
        let held_old = f.root.path().join("held-old");
        let changed = Cell::new(false);
        let policy = Policy {
            check: Some(Box::new(move |_| {
                if !changed.replace(true) {
                    std::fs::rename(&path, &held_old).unwrap();
                    if symlink {
                        std::os::unix::fs::symlink(&held_old, &path).unwrap();
                    } else { std::fs::create_dir(&path).unwrap(); }
                }
                Ok(())
            })),
            ..Policy::default()
        };
        assert_eq!(f.fail(&policy, true), Err(ManagedAreaError::Unverified));
        assert!(std::fs::symlink_metadata(f.path()).is_ok());
        assert!(f.root.path().join("held-old").is_dir());
        let records = policy.records.borrow();
        assert_eq!(records[0].phase, Phase::Explicit);
        assert_eq!(records[0].initialization, Some(ManagedAreaError::Unavailable));
        assert!(records[0].rollback.is_err());
        assert!(records.len() <= 2);
        drop(records);
        f.finish();
    }
}

fn empty_evidence_and_unlink_refusals() {
    // Synthetic population/parser/filesystem-check refusals, not real kernel evidence.
    for error in [ManagedAreaError::Conflict, ManagedAreaError::Unverified,
        ManagedAreaError::Unavailable]
    {
        let f = Fixture::new();
        let policy = Policy { check: Some(Box::new(move |_| Err(error))), ..Policy::default() };
        assert_eq!(f.fail(&policy, true), Err(ManagedAreaError::Unverified));
        assert!(f.path().is_dir());
        let records = policy.records.borrow();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], Diagnostic { phase: Phase::Explicit,
            initialization: Some(ManagedAreaError::Unavailable), rollback: Err(error) });
        assert_eq!(records[1].phase, Phase::Fallback);
        assert_eq!(records[1].rollback, Err(error));
        drop(records);
        f.finish();
    }
    let f = Fixture::new();
    let child = f.path().join("descendant");
    let policy = Policy::default();
    let result: Result<(), ManagedAreaError> = create_using(
        &f.parent, "owned".into(), &policy, |pending| {
            pending.directory()?;
            std::fs::create_dir(&child).unwrap();
            Err(ManagedAreaError::Unavailable)
        },
    );
    assert_eq!(result, Err(ManagedAreaError::Unverified));
    assert!(child.is_dir(), "never recursively remove descendants");
    assert_eq!(policy.records.borrow().len(), 2);
    f.finish();
}

fn disappearance_and_fallback() {
    let f = Fixture::new();
    let path = f.path();
    let removed = Cell::new(false);
    let policy = Policy { check: Some(Box::new(move |_| {
        if !removed.replace(true) { std::fs::remove_dir(&path).unwrap(); }
        Ok(())
    })), ..Policy::default() };
    assert_eq!(f.fail(&policy, true), Err(ManagedAreaError::Unverified));
    assert!(!f.path().exists());
    assert!(policy.records.borrow().iter().all(|record| record.rollback.is_err()));
    f.finish();
    let f = Fixture::new();
    let first = Cell::new(true);
    let policy = Policy { check: Some(Box::new(move |_| {
        if first.replace(false) { Err(ManagedAreaError::Conflict) } else { Ok(()) }
    })), ..Policy::default() };
    assert_eq!(f.fail(&policy, true), Err(ManagedAreaError::Unverified));
    assert!(!f.path().exists());
    let records = policy.records.borrow();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].rollback, Err(ManagedAreaError::Conflict));
    assert_eq!(records[1].rollback, Ok(()));
    assert!(records.iter().all(|record| record.initialization == Some(ManagedAreaError::Unavailable)));
    drop(records);
    f.finish();
}

fn unwind_cleanup() {
    let f = Fixture::new();
    let policy = Policy { panic_diagnostic: true, ..Policy::default() };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _: Result<(), ManagedAreaError> = create_using(
            &f.parent, "owned".into(), &policy, |pending| {
                pending.directory()?;
                panic!("injected pre-publication unwind")
            },
        );
    }));
    assert!(result.is_err());
    assert!(!f.path().exists());
    assert_eq!(policy.records.borrow().as_slice(), &[Diagnostic {
        phase: Phase::Fallback, initialization: None, rollback: Ok(()),
    }]);
    f.finish();
}

#[test]
fn partial_creation_fault_vectors_preserve_ownership() {
    early_and_pinned_failures();
    conflict_and_publication();
    replacement_and_symlink();
    empty_evidence_and_unlink_refusals();
    disappearance_and_fallback();
    unwind_cleanup();
}
