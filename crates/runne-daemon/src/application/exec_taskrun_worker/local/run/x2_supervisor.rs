use runne_platform::local_command_linux::{
    GatedLinuxChild, LinuxCommandSpec, LinuxLeaderExitKindV1, PermissionChildV1,
    PermissionHelperChildV1,
};
use runne_platform::process_managed_area::LinuxManagedArea;
use std::time::Duration;

pub(in crate::application::exec_taskrun_worker::local) enum X2Observation {
    Continue,
    Stop,
    Complete(i32),
    PermissionComplete(LinuxLeaderExitKindV1),
}

pub(in crate::application::exec_taskrun_worker::local) enum X2Outcome {
    Stopped,
    Complete(i32),
    PermissionComplete(LinuxLeaderExitKindV1),
}

pub(super) fn spawn_gated<'a>(
    spec: &LinuxCommandSpec<'_>,
    area: &'a LinuxManagedArea,
) -> Result<GatedLinuxChild<'a>, runne_platform::local_command_linux::LinuxCommandError> {
    spec.spawn_gated(area)
}

/// Shared bounded lifecycle for every child released through the X2 gate.
/// The caller observes durable policy and drains optional output on each tick;
/// this core owns area termination, leader reaping, and empty proof.
pub(super) fn supervise_gated_child(
    child: &mut GatedLinuxChild<'_>,
    area: &LinuxManagedArea,
    interval: Duration,
    mut observe: impl FnMut(&mut GatedLinuxChild<'_>) -> Result<X2Observation, ()>,
) -> Result<X2Outcome, ()> {
    supervise_child(child, area, interval, |child| observe(child))
}

pub(in crate::application::exec_taskrun_worker::local) fn supervise_child<C: X2ChildLifecycle>(
    child: &mut C,
    area: &LinuxManagedArea,
    interval: Duration,
    mut observe: impl FnMut(&mut C) -> Result<X2Observation, ()>,
) -> Result<X2Outcome, ()> {
    loop {
        let observed = match observe(child) {
            Ok(value) => value,
            Err(()) => {
                stop_and_prove(child, area)?;
                return Err(());
            }
        };
        match observed {
            X2Observation::Continue => std::thread::sleep(interval),
            X2Observation::Stop => {
                stop_and_prove(child, area)?;
                return Ok(X2Outcome::Stopped);
            }
            X2Observation::Complete(code) => {
                stop_and_prove(child, area)?;
                return Ok(X2Outcome::Complete(code));
            }
            X2Observation::PermissionComplete(exit) => {
                stop_and_prove(child, area)?;
                return Ok(X2Outcome::PermissionComplete(exit));
            }
        }
    }
}

pub(in crate::application::exec_taskrun_worker::local) trait X2ChildLifecycle {
    fn terminate_area(&self, grace: Duration) -> Result<(), ()>;
    fn reap_after_stop(&mut self, timeout: Duration) -> Result<(), ()>;
}

impl X2ChildLifecycle for GatedLinuxChild<'_> {
    fn terminate_area(&self, grace: Duration) -> Result<(), ()> {
        GatedLinuxChild::terminate_area(self, grace).map_err(|_| ())
    }

    fn reap_after_stop(&mut self, timeout: Duration) -> Result<(), ()> {
        GatedLinuxChild::reap_after_stop(self, timeout).map_err(|_| ())
    }
}

impl X2ChildLifecycle for PermissionHelperChildV1<'_> {
    fn terminate_area(&self, grace: Duration) -> Result<(), ()> {
        PermissionHelperChildV1::terminate_area(self, grace).map_err(|_| ())
    }

    fn reap_after_stop(&mut self, timeout: Duration) -> Result<(), ()> {
        PermissionHelperChildV1::reap_after_stop(self, timeout).map_err(|_| ())
    }
}

impl X2ChildLifecycle for PermissionChildV1<'_> {
    fn terminate_area(&self, grace: Duration) -> Result<(), ()> {
        PermissionChildV1::terminate_area(self, grace).map_err(|_| ())
    }

    fn reap_after_stop(&mut self, timeout: Duration) -> Result<(), ()> {
        PermissionChildV1::reap_after_stop(self, timeout).map_err(|_| ())
    }
}

fn stop_and_prove<C: X2ChildLifecycle>(child: &mut C, area: &LinuxManagedArea) -> Result<(), ()> {
    child.terminate_area(Duration::from_secs(1))?;
    child.reap_after_stop(Duration::from_secs(3))?;
    area.prove_empty().map_err(|_| ())?;
    Ok(())
}
