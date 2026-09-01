use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use super::reap_guard::{ExactWriterCleanup, RetainedWriterCleanup};
use super::reaper_registry::{CredentialWriterReaperRegistry, ReaperOperationId};

#[test]
fn panic_after_ack_stops_and_reaps_the_exact_child_at_every_transcript_step() {
    for step in 0..3 {
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let child = Arc::new(Mutex::new(child));
        let reaped = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&reaped);
        let owned_child = Arc::clone(&child);
        let registry = CredentialWriterReaperRegistry::start(Duration::from_millis(20)).unwrap();
        let cleanup = RetainedWriterCleanup::new(
            ChildReap {
                child: owned_child,
                reaped: observed,
            },
            ReaperOperationId::new(&format!("panic-step-{step}")).unwrap(),
            Arc::clone(&registry),
        );
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _retained = cleanup;
            panic!("injected transcript panic after ACK at step {step}");
        }));
        assert!(unwind.is_err());
        assert!(reaped.load(Ordering::SeqCst));
        assert!(child.lock().expect("child").try_wait().unwrap().is_some());
        assert!(registry.snapshot().is_empty());
        assert!(registry.shutdown());
    }
}

struct ChildReap {
    child: Arc<Mutex<std::process::Child>>,
    reaped: Arc<AtomicBool>,
}

impl ExactWriterCleanup for ChildReap {
    type Error = ();

    fn finish_exact(&mut self) -> Result<(), ()> {
        self.reap()
    }

    fn abort_exact(&mut self) -> Result<(), ()> {
        self.child.lock().map_err(|_| ())?.kill().map_err(|_| ())?;
        self.reap()
    }
}

impl ChildReap {
    fn reap(&self) -> Result<(), ()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if self
                .child
                .lock()
                .map_err(|_| ())?
                .try_wait()
                .map_err(|_| ())?
                .is_some()
            {
                self.reaped.store(true, Ordering::SeqCst);
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
