use runne_platform::local_command_linux::GatedLinuxChild;
use runne_platform::local_command_linux::LinuxCommandSpec;
use runne_platform::process_managed_area::LinuxManagedArea;
use std::time::Duration;

pub(super) enum X2Observation {
    Continue,
    Stop,
    Complete(i32),
}

pub(super) enum X2Outcome {
    Stopped,
    Complete(i32),
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
        }
    }
}

fn stop_and_prove(child: &mut GatedLinuxChild<'_>, area: &LinuxManagedArea) -> Result<(), ()> {
    child
        .terminate_area(Duration::from_secs(1))
        .map_err(|_| ())?;
    child
        .reap_after_stop(Duration::from_secs(3))
        .map_err(|_| ())?;
    area.prove_empty().map_err(|_| ())?;
    Ok(())
}
