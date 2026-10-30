//! Test-only causal pause; the real second root guard remains held during Drop.
use crate::store::taskrun_local_command::{
    PermissionRootFenceGuardV1, PermissionRootFenceOwnerV1, PermissionRootFenceRequestV1,
};
use runne_application::ports::EventStoreError;
use std::{
    fs::File,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender},
    },
    time::{Duration, Instant},
};

pub(super) struct Control {
    armed: AtomicBool,
    acquisitions: AtomicUsize,
    failed: AtomicBool,
    cancel: Arc<AtomicBool>,
    deadline: Mutex<Option<Instant>>,
    revoker: SyncSender<()>,
    observer: SyncSender<()>,
    permit: Mutex<Receiver<()>>,
}

impl Control {
    pub(super) fn new(
        cancel: Arc<AtomicBool>,
        revoker: SyncSender<()>,
        observer: SyncSender<()>,
        permit: Receiver<()>,
    ) -> Arc<Self> {
        Arc::new(Self {
            armed: AtomicBool::new(false),
            acquisitions: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            cancel,
            deadline: Mutex::new(None),
            revoker,
            observer,
            permit: Mutex::new(permit),
        })
    }

    pub(super) fn arm(&self, deadline: Instant) -> Result<(), &'static str> {
        let mut saved = self.deadline.try_lock().map_err(|_| "deadline lock")?;
        if saved.is_some() || self.armed.load(Ordering::SeqCst) {
            return Err("duplicate arm");
        }
        *saved = Some(deadline);
        self.armed.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub(super) fn decorate(
        self: &Arc<Self>,
        original: Arc<dyn PermissionRootFenceOwnerV1>,
    ) -> Arc<dyn PermissionRootFenceOwnerV1> {
        Arc::new(Owner { original, control: self.clone() })
    }

    fn successful(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
            && self.acquisitions.load(Ordering::SeqCst) == 2
            && !self.failed.load(Ordering::SeqCst)
            && !self.cancel.load(Ordering::SeqCst)
    }

    // Retire only after both workers are collected and the exact race proof passed.
    // Later terminal validation must reach the genuine root and terminal barrier.
    pub(super) fn finish(&self) -> Result<(), &'static str> {
        if !self.successful() { return Err("root pause proof failed"); }
        self.armed.compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "race instrumentation already retired")?;
        Ok(())
    }

    fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
        self.cancel.store(true, Ordering::SeqCst);
    }

    fn hold_second_guard(&self) {
        // No assertion/panic, SQL, native-handle access or blocking mutex here.
        let result = (|| {
            if self.cancel.load(Ordering::SeqCst) { return Err(()); }
            self.revoker.try_send(()).map_err(|_| ())?;
            self.observer.try_send(()).map_err(|_| ())?;
            let deadline = self.deadline.try_lock().map_err(|_| ())?
                .ok_or(())?;
            let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
            let wait = remaining.min(Duration::from_secs(3));
            self.permit.try_lock().map_err(|_| ())?
                .recv_timeout(wait).map_err(|_| ())?;
            if self.cancel.load(Ordering::SeqCst) { return Err(()); }
            Ok(())
        })();
        if result.is_err() { self.fail(); }
    }
}

struct Owner {
    original: Arc<dyn PermissionRootFenceOwnerV1>,
    control: Arc<Control>,
}

impl PermissionRootFenceOwnerV1 for Owner {
    fn acquire<'a>(
        &'a self,
        request: &PermissionRootFenceRequestV1,
    ) -> Result<Box<dyn PermissionRootFenceGuardV1 + 'a>, EventStoreError> {
        let original = self.original.acquire(request)?;
        let pause = if self.control.armed.load(Ordering::SeqCst) {
            match self.control.acquisitions.fetch_add(1, Ordering::SeqCst) {
                0 => false,
                1 => true,
                _ => {
                    self.control.fail();
                    return Err(EventStoreError::CorruptData);
                }
            }
        } else { false };
        Ok(Box::new(Guard { original, control: &self.control, pause }))
    }
}

struct Guard<'a> {
    original: Box<dyn PermissionRootFenceGuardV1 + 'a>,
    control: &'a Control,
    pause: bool,
}

impl PermissionRootFenceGuardV1 for Guard<'_> {
    fn workspace(&self) -> &File { self.original.workspace() }
    fn broker_root_version(&self) -> u64 { self.original.broker_root_version() }
    fn broker_root_identity(&self) -> &[u8; 32] { self.original.broker_root_identity() }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        // Rust drops fields AFTER this body: original is held through the wait.
        if self.pause { self.control.hold_second_guard(); }
    }
}
