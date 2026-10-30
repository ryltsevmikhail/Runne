use crate::store::LocalCommandPermissionTerminalOutputV1;
use runne_application::permission_modes::LocalCommandPermissionBindingV1;
use runne_platform::{
    local_command_linux::PermissionChildV1,
    process_managed_area::{LinuxManagedArea, LinuxManagedAreaRoot, ManagedAreaBinding},
};
use std::time::{Duration, Instant};

pub(super) struct Area(Option<LinuxManagedArea>);
impl Area {
    pub(super) fn new(b: &LocalCommandPermissionBindingV1) -> Self {
        let root = LinuxManagedAreaRoot::open_current_cgroup()
            .expect("NOTRUN: exclusive delegated disposable guest cgroup required");
        let a = b.assignment();
        Self(Some(
            root.create_area(
                ManagedAreaBinding::new(
                    *a.taskrun_id.as_bytes(),
                    *a.attempt_id.as_bytes(),
                    *b.invocation_id().as_bytes(),
                )
                .unwrap(),
            )
            .unwrap(),
        ))
    }
    pub(super) fn get(&self) -> &LinuxManagedArea {
        self.0.as_ref().unwrap()
    }
    pub(super) fn finish(mut self) {
        self.get().prove_empty().unwrap().revalidate().unwrap();
        self.0.take().unwrap().remove_empty().unwrap();
    }
}
impl Drop for Area {
    fn drop(&mut self) {
        if let Some(area) = self.0.take() {
            // Called after Child drops; remove_empty independently verifies identity/empty.
            eprintln!("G2_FAILURE_AREA_CLEANUP {:?}", area.remove_empty());
        }
    }
}

pub(super) struct Child<'a> {
    pub(super) child: PermissionChildV1<'a>,
    armed: bool,
}
impl<'a> Child<'a> {
    pub(super) fn new(child: PermissionChildV1<'a>) -> Self {
        Self { child, armed: true }
    }
    pub(super) fn stop_reap(&mut self) {
        let stop = self.child.terminate_area(Duration::from_millis(20));
        let reap = self.child.reap_after_stop(Duration::from_secs(2));
        // Attempt reap before checking stop: both failures remain test failures.
        stop.expect("owned held child stop");
        reap.expect("owned direct leader reap");
    }
    pub(super) fn drain(&mut self) -> LocalCommandPermissionTerminalOutputV1 {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            self.child.poll_output().unwrap();
            let c = self.child.take_output();
            assert!(c.stdout.is_empty() && c.stderr.is_empty());
            assert_eq!((c.stdout_observed_bytes, c.stderr_observed_bytes), (0, 0));
            assert!(!c.stdout_truncated && !c.stderr_truncated && !c.observed_bytes_overflowed);
            if c.stdout_eof && c.stderr_eof {
                return LocalCommandPermissionTerminalOutputV1::new(
                    c.stdout,
                    c.stderr,
                    c.stdout_observed_bytes,
                    c.stderr_observed_bytes,
                    c.stdout_truncated,
                    c.stderr_truncated,
                    c.stdout_eof,
                    c.stderr_eof,
                    c.observed_bytes_overflowed,
                )
                .unwrap();
            }
            assert!(Instant::now() < deadline, "bounded both-EOF drain");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub(super) fn evidence(&self, area: &LinuxManagedArea) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while area.is_populated().unwrap() {
            assert!(Instant::now() < deadline, "bounded recursive empty wait");
            std::thread::sleep(Duration::from_millis(5));
        }
        let e = self.child.terminal_evidence().unwrap();
        assert_eq!(e.area_identity(), &area.identity().to_bytes());
        e.revalidate_empty_area().unwrap();
        area.prove_empty().unwrap().revalidate().unwrap();
    }
    pub(super) fn disarm(&mut self) {
        // Call only after drain plus terminal evidence; fallback is never passing evidence.
        self.child
            .terminal_evidence()
            .unwrap()
            .revalidate_empty_area()
            .unwrap();
        self.armed = false;
    }
}
impl Drop for Child<'_> {
    fn drop(&mut self) {
        if self.armed {
            let stop = self.child.terminate_area(Duration::from_millis(20));
            let reap = self.child.reap_after_stop(Duration::from_secs(2));
            eprintln!("G2_FAILURE_CHILD_CLEANUP stop={stop:?} reap={reap:?}");
        }
    }
}
