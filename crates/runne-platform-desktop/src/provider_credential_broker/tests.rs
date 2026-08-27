use super::*;
use runne_platform_ports::provider_credential_broker::ProviderCredentialBrokerPort;
use std::path::PathBuf;

#[derive(Default)]
struct FakeProcess {
    kills: u8,
    reaps: u8,
    start: [u8; 32],
}
impl RetainedWriterProcess for FakeProcess {
    fn writer_start_identity(&self) -> Result<[u8; 32], BrokerHandoffError> {
        Ok(self.start)
    }

    fn terminate_retained_child(&mut self) -> Result<(), BrokerHandoffError> {
        self.kills += 1;
        Ok(())
    }
    fn reap_retained_child(&mut self) -> Result<(), BrokerHandoffError> {
        self.reaps += 1;
        Ok(())
    }
}

fn evidence() -> WriterProcessEvidence {
    WriterProcessEvidence::test_only([1; 32], [2; 32], [3; 32])
}

fn process() -> FakeProcess {
    FakeProcess {
        start: [1; 32],
        ..FakeProcess::default()
    }
}

#[test]
fn broker_rejects_duplicate_transfer_and_tauri_kill_after_daemon_ack() {
    let mut broker = PlatformCredentialBroker::new(process(), evidence()).unwrap();
    broker.transfer_to_daemon().unwrap();
    assert_eq!(
        broker.transfer_to_daemon(),
        Err(BrokerHandoffError::Rejected)
    );
    broker.acknowledge_daemon_kill_capability().unwrap();
    assert_eq!(
        broker.terminate_exact_retained_child(),
        Err(BrokerHandoffError::Rejected)
    );
    broker.reap_exact_retained_child().unwrap();
    assert_eq!(broker.ownership_state(), WriterOwnershipState::Reaped);
}

#[test]
fn broker_rejects_pid_reuse_and_mixed_child_evidence() {
    assert_eq!(
        PlatformCredentialBroker::new(
            process(),
            WriterProcessEvidence::test_only([0; 32], [2; 32], [3; 32])
        )
        .map(|_| ()),
        Err(BrokerHandoffError::Rejected),
    );

    assert_eq!(
        PlatformCredentialBroker::new(
            FakeProcess {
                start: [9; 32],
                ..FakeProcess::default()
            },
            evidence(),
        )
        .map(|_| ()),
        Err(BrokerHandoffError::Rejected),
    );
}

#[cfg(target_os = "linux")]
#[test]
fn verified_unix_launch_binds_evidence_to_the_retained_child() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("writer-fixture");
    std::fs::write(
        &executable,
        "#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = \"__provider-credential-broker-v1\" ] || exit 11\nIFS= read -r _\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let artifact = runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact::new(
        executable, [1; 32], [2; 32],
    )
    .unwrap();
    let spec = runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec::new(
        artifact,
    );

    let (_endpoints, process, evidence) = spawn_unix_writer(&spec).unwrap();
    let mut broker = PlatformCredentialBroker::new(process, evidence).unwrap();
    broker.terminate_exact_retained_child().unwrap();
    broker.reap_exact_retained_child().unwrap();
}

#[test]
fn writer_command_clears_environment_and_uses_only_the_fixed_mode() {
    let artifact = runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact::new(
        PathBuf::from("/bundle/runne"),
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let spec = runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec::new(
        artifact,
    );

    let command = writer_command(&spec);

    assert_eq!(command.get_program(), "/bundle/runne");
    assert_eq!(command.get_args().collect::<Vec<_>>(), ["__provider-credential-broker-v1"]);
    assert_eq!(command.get_envs().count(), 0);
}

#[cfg(unix)]
#[test]
fn writer_command_binds_control_and_secret_to_fixed_inherited_descriptors() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("writer-fixture");
    std::fs::write(
        &executable,
        "#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = \"__provider-credential-broker-v1\" ] || exit 11\nIFS= read -r control || exit 12\nprintf reply >&2\nIFS= read -r secret <&1 || exit 13\n[ \"$control\" = control ] && [ \"$secret\" = secret ] || exit 14\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let artifact = runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact::new(
        executable,
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let spec = runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec::new(
        artifact,
    );
    let (mut endpoints, child_channels) = UnixWriterBrokerEndpoints::pair().unwrap();
    let mut command = writer_command(&spec);
    configure_unix_writer_channels(&mut command, child_channels).unwrap();

    let mut child = command.spawn().unwrap();
    endpoints.send_control(b"control\n").unwrap();
    assert_eq!(endpoints.read_control_exact(5).unwrap(), b"reply");
    endpoints
        .send_secret(
            runne_platform_ports::provider_credential_prompt::SecureCredentialMaterial::new(
                b"secret".to_vec(),
            )
            .unwrap()
            .into_pipe_bytes(),
        )
        .unwrap();

    assert!(child.wait().unwrap().success());
}

#[cfg(unix)]
#[test]
fn writer_control_rejects_oversized_response_before_reading() {
    let (mut endpoints, child_channels) = UnixWriterBrokerEndpoints::pair().unwrap();
    drop(child_channels);

    assert_eq!(
        endpoints.read_control_exact(4_097),
        Err(BrokerHandoffError::Rejected)
    );
}
