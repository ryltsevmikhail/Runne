//! Owned handles only; finite ordinary-failure cleanup, no global process discovery.
use runne_application::permission_modes::LocalCommandPermissionBindingV1;
use runne_platform::{
    local_command_linux::PermissionChildV1,
    process_managed_area::{LinuxManagedArea, LinuxManagedAreaRoot, ManagedAreaBinding},
};
use std::time::Duration;

pub(super) struct Area(Option<LinuxManagedArea>);
impl Area {
    pub(super) fn new(b: &LocalCommandPermissionBindingV1) -> Self {
        let root =
            LinuxManagedAreaRoot::open_current_cgroup().expect("R08/NOTRUN: delegated guest root");
        let id = b.assignment();
        let area = root
            .create_area(
                ManagedAreaBinding::new(
                    *id.taskrun_id.as_bytes(),
                    *id.attempt_id.as_bytes(),
                    *b.invocation_id().as_bytes(),
                )
                .unwrap(),
            )
            .expect("fresh owned guest area");
        Self(Some(area))
    }
    pub(super) fn get(&self) -> &LinuxManagedArea {
        self.0.as_ref().unwrap()
    }
    pub(super) fn finish(mut self) {
        // Keep ownership armed until all fallible proof checks have passed.
        self.get().prove_empty().unwrap().revalidate().unwrap();
        self.0
            .take()
            .unwrap()
            .remove_empty()
            .expect("remove proven empty owned area");
    }
}
impl Drop for Area {
    fn drop(&mut self) {
        if let Some(area) = self.0.take() {
            // Child guard drops first. Never remove a populated or unverified area.
            let result = area.remove_empty();
            eprintln!("R08_FAILURE_AREA_CLEANUP {result:?}");
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
    pub(super) fn verified_terminal(&mut self) {
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
            eprintln!("R08_FAILURE_CHILD_CLEANUP stop={stop:?} reap={reap:?}");
        }
    }
}
