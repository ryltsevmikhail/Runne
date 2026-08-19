use std::sync::{Arc, Mutex, mpsc::SyncSender, mpsc::sync_channel};

use runne_tools::{ProcessStubDisposition, SandboxQualificationProbe};

use super::super::super::runtime::process_ledger::ProcessPhaseOutcome;
use super::super::super::{FixtureApprovalPolicy, FixtureAuditProcessPhase};
use super::super::routing::support::{Probe, process_phases, ready};

struct BlockingContainmentProbe {
    entered: SyncSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl SandboxQualificationProbe for BlockingContainmentProbe {
    fn qualify(&self) -> Result<(), ProcessStubDisposition> {
        self.entered.send(()).expect("test receiver remains open");
        self.release
            .lock()
            .expect("test release lock")
            .recv()
            .expect("test release sender remains open");
        Ok(())
    }
}

#[test]
fn reentrant_containment_probe_releases_fixture_state() {
    let (entered_sender, entered_receiver) = sync_channel(0);
    let (release_sender, release_receiver) = sync_channel(0);
    let probe = Arc::new(BlockingContainmentProbe {
        entered: entered_sender,
        release: Mutex::new(release_receiver),
    });
    let fixture = ready(
        Probe::Controlled(probe),
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let (key, payload) = super::super::routing::support::key_payload(&fixture, "reentrant-audit");

    std::thread::scope(|scope| {
        let dispatch = scope.spawn(|| {
            fixture
                .runtime
                .dispatch_process_gateway_for_test(key, payload)
        });
        entered_receiver.recv().expect("probe entered containment");
        assert_eq!(
            process_phases(&fixture.runtime),
            [FixtureAuditProcessPhase::Reserved]
        );
        release_sender.send(()).expect("probe release accepted");
        assert!(matches!(
            dispatch.join().expect("dispatch thread completes"),
            Ok(ProcessPhaseOutcome::EffectUncertain { .. })
        ));
    });
}
