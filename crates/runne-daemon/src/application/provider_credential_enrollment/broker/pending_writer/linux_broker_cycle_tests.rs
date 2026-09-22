//! Real writer + production Linux broker + SQLite issue/claim/effect state.
//! The child's store remains fake; no native qualification or ACTIVE proof.
use super::*;
use crate::application::provider_credential_enrollment::broker::{
    pending_writer::launch_linux_writer_with_handshake, unix_linux::LinuxCredentialBrokerChannel,
};
use crate::application::provider_credential_enrollment::tests::broker_support;
use runne_platform_desktop::provider_credential_broker as platform;
use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};
use runne_provider::{CredentialMeasurementSnapshot, CredentialOperationState};
use sha2::{Digest as _, Sha256};
use std::{
    io::Read as _,
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
};

struct Channel(Option<LinuxCredentialBrokerChannel>);
impl Drop for Channel {
    fn drop(&mut self) {
        if let Some(channel) = self.0.take() {
            channel.terminate_exact_writer();
        }
    }
}

#[test]
#[ignore = "requires Linux owner session bus; builds a CLI example with fake store"]
fn linux_real_writer_drives_durable_broker_without_activating_before_readback() {
    cycle(false);
}

#[test]
#[ignore = "requires Linux owner session bus; uses a shared directory fake store"]
fn linux_real_writer_completes_only_after_shared_daemon_readback() {
    cycle(true);
}

fn cycle(shared: bool) {
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    let fixture = broker_support::fixture();
    let release = fixture
        .operation
        .metadata()
        .qualified_release_tuple_digest()
        .unwrap();
    let built_binary = cycle_binary();
    let binary = if shared {
        use std::os::unix::fs::PermissionsExt as _;
        let fake_root = fixture._directory.path().join("fixture-store");
        std::fs::create_dir(&fake_root).unwrap();
        std::fs::set_permissions(&fake_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let copied = fixture._directory.path().join("writer_cycle_fixture");
        std::fs::copy(built_binary, &copied).unwrap();
        copied
    } else {
        built_binary
    };
    let image: [u8; 32] = Sha256::digest(std::fs::read(&binary).unwrap()).into();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(binary, image, release.as_bytes()).unwrap(),
    );
    let spawned_spec = spec.clone();
    let (daemon, writer) = UnixStream::pair().unwrap();
    daemon
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    daemon
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut readback_marker = daemon.try_clone().unwrap();
    let channel_binding = [21; 32];
    let authority = DaemonBrokerAuthority::for_test_endpoint(channel_binding, daemon);
    let key = authority.publication_public_key();
    let binding = PendingBrokerRendezvousBinding {
        operation_id: fixture.operation.operation_id(),
        begin_proof: fixture.operation.begin_proof_digest(),
        owner: fixture.operation.installation_owner_id(),
        protected_session: [17; 32],
        tauri_peer: [12; 32],
        daemon_authority: [16; 32],
        database_generation: 7,
        supervisor_generation: 8,
        release_tuple: release,
        expires_at_high_water: 4_000_000_000,
    };
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let (startup_authority, _) = transfer_authority(&issuer, [31; 32], [17; 32]);
    let (handoff_authority, authenticator) = transfer_authority(&issuer, [31; 32], [17; 32]);
    let (sender, receiver) = UnixStream::pair().unwrap();
    let prepared = platform::prepare_daemon_owned_writer_endpoint_handoff(
        receiver,
        &authenticator,
        channel_binding,
        key,
    )
    .unwrap();
    let relay_slot = Arc::new(Mutex::new(None));
    let spawned_relay = Arc::clone(&relay_slot);
    let spawn = Box::new(move |endpoint, startup| {
        let sender = std::thread::spawn(move || {
            platform::send_daemon_owned_writer_endpoint(
                sender,
                endpoint,
                &handoff_authority,
                channel_binding,
                key,
            )
        });
        let result = platform::spawn_linux_pair_writer_from_prepared_handoff(
            &spawned_spec,
            prepared,
            startup,
            &authenticator,
        );
        sender.join().unwrap().unwrap();
        let (process, relay) =
            result.map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::Unavailable)?;
        *spawned_relay.lock().unwrap() = Some(relay);
        Ok(process)
    });
    let mut owned = Channel(Some(
        launch_linux_writer_with_handshake(
            LinuxWriterLaunchInputs {
                rendezvous: authority,
                control_end_for_writer: writer,
                binding,
                transfer_authority: startup_authority,
                launch_secret: [31; 32],
                daemon_image: Sha256::digest(
                    std::fs::read(std::env::current_exe().unwrap()).unwrap(),
                )
                .into(),
            },
            &spec,
            spawn,
        )
        .expect("real pidfd/startup admission"),
    ));
    let channel = owned.0.as_mut().unwrap();
    let facts = measurements(&fixture, channel);
    let context = fixture
        .broker
        .claim_issue_context(facts.clone(), channel_binding, fixture.continuation, 7, 8)
        .unwrap();
    let receipt = fixture
        .broker
        .issue_ticket(
            fixture.operation.clone(),
            fixture.continuation,
            &context,
            60,
            &fixture.store,
            channel,
        )
        .expect("durable ticket and real Linux attestation");
    let mut claimed = fixture
        .broker
        .claim_ticket_from_channel(
            receipt,
            fixture.continuation,
            7,
            8,
            facts,
            &fixture.store,
            channel,
        )
        .expect("writer claim and durable ACK");
    assert!(
        fixture
            .store
            .lifecycle_snapshot(fixture.operation.provider())
            .unwrap()
            .active_version()
            .is_none()
    );
    let frame = claimed.take_secret_relay().unwrap().unwrap();
    relay_slot
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .seal_and_write(
            &frame,
            zeroize::Zeroizing::new(b"daemon-cycle-fixture-key".to_vec()),
        )
        .unwrap();
    fixture
        .broker
        .release_claimed_effect_to_channel(&claimed, channel)
        .unwrap();
    let observed = fixture
        .broker
        .observe_effect_from_channel(claimed, &fixture.store, channel)
        .expect("real writer effect observation");
    assert_eq!(
        observed.state(),
        CredentialOperationState::NativeEffectObserved
    );
    assert_eq!(
        fixture
            .store
            .load_operation(fixture.operation.operation_id())
            .unwrap()
            .state(),
        CredentialOperationState::NativeEffectObserved
    );
    let mut marker = [0; 8];
    readback_marker
        .read_exact(&mut marker)
        .expect("child fake-store version is readable");
    assert_eq!(&marker, b"readback");
    // A writer report (or a test marker) is not daemon-authoritative readback.
    assert!(
        fixture
            .store
            .lifecycle_snapshot(fixture.operation.provider())
            .unwrap()
            .active_version()
            .is_none()
    );
    drop(owned);
    if shared {
        assert_daemon_presence_completes(fixture, spec.executable());
    } else {
        assert_daemon_absence_wins(fixture, spec.executable());
    }
}

#[path = "linux_broker_cycle_support.rs"]
mod support;
use support::*;

#[path = "linux_broker_cycle_completion.rs"]
mod completion;
use completion::assert_daemon_presence_completes;
