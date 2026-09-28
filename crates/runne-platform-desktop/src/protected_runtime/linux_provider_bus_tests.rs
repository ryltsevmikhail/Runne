use std::os::unix::net::UnixListener;
use std::process::Command;

use super::ProtectedBundledRuntimeLaunchSpec;
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

/// Builds one valid launch spec rooted in the fixture directory; the
/// executable satisfies the strict absolute/regular/owner-executable checks.
fn fixture_launch_spec(directory: &tempfile::TempDir) -> ProtectedBundledRuntimeLaunchSpec {
    use std::os::unix::fs::PermissionsExt as _;
    let executable = directory.path().join("controlled-executable");
    std::fs::write(&executable, b"fixture executable").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    ProtectedBundledRuntimeLaunchSpec::new(&executable, &directory.path().join("runtime")).unwrap()
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
    let directory = tempfile::tempdir().unwrap();
    let spec = fixture_launch_spec(&directory);
    assert!(address_for_launch(&spec).unwrap().is_none());
    let (_directory, _listener, address) = fixture_bus();
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

#[test]
fn injected_validated_bus_address_satisfies_provider_bound_launch_without_host_bus() {
    let (directory, _listener, address) = fixture_bus();
    let socket_path = directory.path().join("session-bus.sock");
    let spec = fixture_launch_spec(&directory)
        .with_openai_provider_activation()
        .with_validated_session_bus_address(&socket_path)
        .unwrap();
    let resolved = address_for_launch(&spec)
        .unwrap()
        .expect("injected address");
    assert_eq!(resolved.as_str(), address.as_str());
}

#[test]
fn seam_rejects_paths_that_are_not_strictly_validated_sockets() {
    let directory = tempfile::tempdir().unwrap();
    let regular_file = directory.path().join("not-a-socket");
    std::fs::write(&regular_file, b"fixture").unwrap();
    let spec = fixture_launch_spec(&directory);
    assert_eq!(
        spec.with_validated_session_bus_address(&regular_file),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );
}
