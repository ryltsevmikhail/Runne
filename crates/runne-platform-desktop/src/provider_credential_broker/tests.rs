use std::path::PathBuf;

use runne_platform_ports::provider_credential_broker::ProviderCredentialBrokerPort;

use super::*;

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

#[test]
fn writer_command_clears_environment_and_uses_only_the_fixed_mode() {
    let artifact = runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact::new(
        PathBuf::from("/bundle/runne"),
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let spec =
        runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec::new(artifact);

    let command = launch::writer_command(&spec);

    assert_eq!(command.get_program(), "/bundle/runne");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        ["__provider-credential-broker-v1"]
    );
    assert_eq!(command.get_envs().count(), 0);
}
