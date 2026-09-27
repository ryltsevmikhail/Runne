use std::os::unix::net::UnixListener;
use std::process::Command;

use crate::{
    ProtectedBundledRuntimeError,
    protected_runtime::linux_provider_bus::{address_for_launch, apply_to_command},
    provider_credential_broker::ValidatedLinuxSessionBusAddress,
};

fn fixture_bus() -> (
    tempfile::TempDir,
    UnixListener,
    ValidatedLinuxSessionBusAddress,
) {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("session-bus.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let address = ValidatedLinuxSessionBusAddress::for_tests(&socket).unwrap();
    (directory, listener, address)
}

fn command_environment(command: &Command) -> Vec<(String, Option<String>)> {
    command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|value| value.to_string_lossy().into_owned()),
            )
        })
        .collect()
}

#[test]
fn provider_bound_launch_sets_only_the_validated_bus_address() {
    let (_directory, _listener, address) = fixture_bus();
    let mut command = Command::new("/bin/true");
    command
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/untrusted/bus")
        .env("XDG_DATA_HOME", "/untrusted/data")
        .env("DISPLAY", ":9876");
    command.env_clear();
    apply_to_command(&mut command, true, Some(&address)).unwrap();

    assert_eq!(
        command_environment(&command),
        vec![(
            "DBUS_SESSION_BUS_ADDRESS".to_owned(),
            Some(address.as_str().to_owned())
        )]
    );
}

#[test]
fn non_provider_launch_stays_environment_empty() {
    let (_directory, _listener, address) = fixture_bus();
    assert!(address_for_launch(false).unwrap().is_none());
    let mut command = Command::new("/bin/true");
    command.env_clear();
    apply_to_command(&mut command, false, Some(&address)).unwrap();
    assert!(command_environment(&command).is_empty());
}

#[test]
fn missing_or_invalid_provider_bus_fails_closed_before_environment_addition() {
    let mut command = Command::new("/bin/true");
    command.env_clear();
    assert_eq!(
        apply_to_command(&mut command, true, None),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );
    assert!(command_environment(&command).is_empty());

    let directory = tempfile::tempdir().unwrap();
    let regular_file = directory.path().join("not-a-socket");
    std::fs::write(&regular_file, b"fixture").unwrap();
    assert!(ValidatedLinuxSessionBusAddress::for_tests(&regular_file).is_err());
}
