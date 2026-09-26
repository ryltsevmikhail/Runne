//! Exact spawn plan surface (B3 seam), split from the pidfd spawn core so
//! each responsibility stays bounded. The plan pins: argv, the fixed
//! `DBUS_SESSION_BUS_ADDRESS` environment entry, stdin ← broker control
//! socket, stdout ← private writer startup (handshake) socket, stderr ←
//! null, and the defense-in-depth close snapshot. Test-support may add one
//! validated private fixture path for the Linux post-delete kill barrier.

use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::path::Path;
#[cfg(any(
    feature = "test-support",
    feature = "linux-native-enrollment-qualification"
))]
use std::path::PathBuf;

use nix::fcntl::OFlag;
use nix::spawn::PosixSpawnFileActions;
use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

use super::SessionBusAddress;

/// The exact spawn surface, pinned by tests (B3 seam).
pub struct SpawnPlan {
    pub argv: Vec<CString>,
    pub environment: Vec<CString>,
    /// (source descriptor, child descriptor) duplications.
    pub duplications: Vec<(i32, i32)>,
    /// Parent descriptors explicitly closed in the child.
    pub closes: Vec<i32>,
}

#[cfg(test)]
pub(in crate::provider_credential_broker) fn build_plan_for_tests(
    spec: &VerifiedWriterLaunchSpec,
    address: &SessionBusAddress,
    channel_fd: i32,
    handshake_fd: i32,
    stderr_fd: i32,
) -> Result<SpawnPlan, BrokerHandoffError> {
    build_plan(
        spec,
        address,
        channel_fd,
        handshake_fd,
        stderr_fd,
        None,
        None,
    )
}

#[cfg(all(test, feature = "test-support"))]
pub(in crate::provider_credential_broker) fn build_plan_for_tests_with_fixture_root(
    spec: &VerifiedWriterLaunchSpec,
    address: &SessionBusAddress,
    channel_fd: i32,
    handshake_fd: i32,
    stderr_fd: i32,
    fixture_root: Option<&Path>,
) -> Result<SpawnPlan, BrokerHandoffError> {
    build_plan(
        spec,
        address,
        channel_fd,
        handshake_fd,
        stderr_fd,
        None,
        fixture_root,
    )
}

pub(in crate::provider_credential_broker) fn build_plan(
    spec: &VerifiedWriterLaunchSpec,
    address: &SessionBusAddress,
    channel_fd: i32,
    handshake_fd: i32,
    stderr_fd: i32,
    secret_fd: Option<i32>,
    fixture_root: Option<&Path>,
) -> Result<SpawnPlan, BrokerHandoffError> {
    if [channel_fd, handshake_fd, stderr_fd]
        .into_iter()
        .chain(secret_fd)
        .any(|fd| fd <= 3)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let executable = CString::new(spec.executable().to_string_lossy().as_bytes())
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let mode = CString::new(spec.arguments()[0]).map_err(|_| BrokerHandoffError::Rejected)?;
    let mut plan = SpawnPlan {
        argv: vec![executable, mode],
        environment: vec![
            CString::new(format!("DBUS_SESSION_BUS_ADDRESS={}", address.as_str()))
                .map_err(|_| BrokerHandoffError::Rejected)?,
        ],
        duplications: vec![
            (channel_fd, libc::STDIN_FILENO),
            (handshake_fd, libc::STDOUT_FILENO),
            (stderr_fd, libc::STDERR_FILENO),
        ],
        closes: vec![channel_fd, handshake_fd, stderr_fd],
    };
    if let Some(root) = fixture_root {
        #[cfg(any(
            feature = "test-support",
            feature = "linux-native-enrollment-qualification"
        ))]
        plan.environment.push(fixture_root_environment(root)?);
        #[cfg(not(any(
            feature = "test-support",
            feature = "linux-native-enrollment-qualification"
        )))]
        let _ = root;
        #[cfg(not(any(
            feature = "test-support",
            feature = "linux-native-enrollment-qualification"
        )))]
        return Err(BrokerHandoffError::Rejected);
    }
    if let Some(secret_fd) = secret_fd {
        plan.duplications.push((secret_fd, 3));
        plan.closes.push(secret_fd);
    }
    Ok(plan)
}

#[cfg(all(
    target_os = "linux",
    any(
        feature = "test-support",
        feature = "linux-native-enrollment-qualification"
    )
))]
pub(super) fn opted_in_fixture_root() -> Result<Option<PathBuf>, BrokerHandoffError> {
    crate::provider_credential_broker::linux_native_enrollment_qualification::fixture_root_from_env(
    )
    .map_err(|_| BrokerHandoffError::Rejected)
}

#[cfg(any(
    feature = "test-support",
    feature = "linux-native-enrollment-qualification"
))]
fn fixture_root_environment(root: &Path) -> Result<CString, BrokerHandoffError> {
    use std::os::unix::ffi::OsStrExt as _;
    let validated = crate::provider_credential_broker::linux_native_enrollment_qualification::validate_fixture_root(root)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let mut value = format!(
        "{}=",
        crate::provider_credential_broker::linux_native_enrollment_qualification::FIXTURE_ROOT_ENV
    )
    .into_bytes();
    value.extend_from_slice(validated.as_os_str().as_bytes());
    CString::new(value).map_err(|_| BrokerHandoffError::Rejected)
}

pub(super) fn apply_plan(plan: &SpawnPlan) -> Result<PosixSpawnFileActions, BrokerHandoffError> {
    let mut actions = PosixSpawnFileActions::init().map_err(|_| BrokerHandoffError::Unavailable)?;
    for (source, target) in &plan.duplications {
        actions
            .add_dup2(*source, *target)
            .map_err(|_| BrokerHandoffError::Unavailable)?;
    }
    for fd in &plan.closes {
        actions
            .add_close(*fd)
            .map_err(|_| BrokerHandoffError::Unavailable)?;
    }
    Ok(actions)
}

/// Defense-in-depth close set from the spawn-time descriptor snapshot.
pub(super) fn close_inventory(
    actions: &mut PosixSpawnFileActions,
    duplicated_channel: &OwnedFd,
    retain_secret: bool,
) -> Result<(), BrokerHandoffError> {
    let keep: [i32; 3] = [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO];
    let inventory =
        std::fs::read_dir("/proc/self/fd").map_err(|_| BrokerHandoffError::Unavailable)?;
    let mut descriptors: Vec<i32> = inventory
        .flatten()
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
        .collect();
    descriptors.sort_unstable();
    descriptors.dedup();
    for fd in descriptors {
        if fd == duplicated_channel.as_fd().as_raw_fd()
            || keep.contains(&fd)
            || (retain_secret && fd == 3)
        {
            continue;
        }
        actions
            .add_close(fd)
            .map_err(|_| BrokerHandoffError::Unavailable)?;
    }
    Ok(())
}

pub(super) fn open_null(flags: OFlag) -> Result<OwnedFd, BrokerHandoffError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(flags.bits());
    }
    let file = options
        .open("/dev/null")
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    Ok(file.into())
}

pub(super) fn duplicate_above_reserved(
    descriptor: &impl AsFd,
) -> Result<OwnedFd, BrokerHandoffError> {
    rustix::io::fcntl_dupfd_cloexec(descriptor, 4).map_err(|_| BrokerHandoffError::Unavailable)
}

#[cfg(all(test, feature = "linux-native-enrollment-qualification"))]
#[test]
fn qualification_plan_forwards_only_the_validated_private_fixture_root() {
    use super::SessionBusAddress;
    use runne_platform_ports::provider_credential_broker::{
        VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
    };
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("fixture");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bus_path = parent.path().join("bus");
    let _bus = UnixListener::bind(&bus_path).unwrap();
    let address = SessionBusAddress::for_tests(&bus_path).unwrap();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new("/bundle/runne".into(), [1; 32], [2; 32]).unwrap(),
    );

    let with_fixture = build_plan(&spec, &address, 10, 11, 12, None, Some(&root)).unwrap();
    assert_eq!(with_fixture.environment.len(), 2);
    assert!(with_fixture.environment.iter().any(|value| {
        value.to_bytes().starts_with(
            format!("{}=", crate::provider_credential_broker::linux_native_enrollment_qualification::FIXTURE_ROOT_ENV).as_bytes(),
        )
    }));
    let default = build_plan(&spec, &address, 10, 11, 12, None, None).unwrap();
    assert_eq!(default.environment.len(), 1);
}

#[cfg(all(
    test,
    not(any(
        feature = "test-support",
        feature = "linux-native-enrollment-qualification"
    ))
))]
#[test]
fn default_plan_rejects_qualification_fixture_forwarding() {
    use super::SessionBusAddress;
    use runne_platform_ports::provider_credential_broker::{
        VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
    };
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("fixture");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bus_path = parent.path().join("bus");
    let _bus = UnixListener::bind(&bus_path).unwrap();
    let address = SessionBusAddress::for_tests(&bus_path).unwrap();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new("/bundle/runne".into(), [1; 32], [2; 32]).unwrap(),
    );
    assert!(build_plan(&spec, &address, 10, 11, 12, None, Some(&root)).is_err());
    assert_eq!(
        build_plan(&spec, &address, 10, 11, 12, None, None)
            .unwrap()
            .environment
            .len(),
        1
    );
}
