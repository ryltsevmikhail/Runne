use super::*;
use runne_platform_ports::provider_credential_broker::ProviderCredentialBrokerPort;

#[derive(Default)]
struct FakeProcess {
    kills: u8,
    reaps: u8,
}
impl RetainedWriterProcess for FakeProcess {
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

#[test]
fn broker_rejects_duplicate_transfer_and_tauri_kill_after_daemon_ack() {
    let mut broker = PlatformCredentialBroker::new(FakeProcess::default(), evidence()).unwrap();
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
            FakeProcess::default(),
            WriterProcessEvidence::test_only([0; 32], [2; 32], [3; 32])
        )
        .map(|_| ()),
        Err(BrokerHandoffError::Rejected),
    );
}
