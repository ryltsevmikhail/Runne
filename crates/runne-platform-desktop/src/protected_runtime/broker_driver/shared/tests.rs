use super::*;
use crate::protected_runtime::{
    PreparedCredentialServiceRejoin, RegisteredCredentialServiceSession,
    credential_discovery::{prepare, reap},
    read_frame, test_only_ready_v3_enrollment_supervisor, write_frame,
};
use runne_api::{
    CredentialServiceRejoinBinding, CredentialServiceSessionAuthenticator, ProtectedActivationKeys,
    ProtectedCredentialEnrollmentOwnedLaunchV3,
};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

#[derive(Clone, Copy, Default)]
enum Reply {
    #[default]
    Ready,
    KillAck,
}

#[derive(Clone, Copy, Default)]
struct Case {
    tamper: bool,
    reply: Reply,
    repeat: bool,
    stale: bool,
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_ready_services_rejoin_outside_supervisor_mutex() {
    check(Case::default()).await;
    check(Case {
        tamper: true,
        ..Case::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_kill_ack_services_rejoin_without_repeating_registration() {
    check(Case {
        reply: Reply::KillAck,
        ..Case::default()
    })
    .await;
    check(Case {
        reply: Reply::KillAck,
        tamper: true,
        ..Case::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_second_rejoin_is_rejected_before_another_service_call() {
    check(Case {
        repeat: true,
        ..Case::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_changed_bootstrap_rejects_registration_before_delivery() {
    check(Case {
        stale: true,
        ..Case::default()
    })
    .await;
}

struct Registration<R> {
    inner: R,
    calls: Arc<AtomicUsize>,
    invalidate: Option<Arc<Mutex<ProtectedBundledRuntimeSupervisor>>>,
}
impl<R: RejoinRegistration> RejoinRegistration for Registration<R> {
    #[allow(
        clippy::future_not_send,
        reason = "registration future is polled on the retained blocking owner, never spawned"
    )]
    async fn register(
        &self,
        prepared: PreparedCredentialServiceRejoin,
    ) -> Result<RegisteredCredentialServiceSession, ProtectedBundledRuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let registered = self.inner.register(prepared).await?;
        if let Some(supervisor) = &self.invalidate {
            supervisor
                .lock()
                .unwrap()
                .process
                .as_mut()
                .unwrap()
                .enrollment_broker_facts = None;
        }
        Ok(registered)
    }
}

async fn check(case: Case) {
    let fixture = test_only_ready_v3_enrollment_supervisor();
    let owned = fixture.owned_launch().unwrap();
    let context = ProviderCredentialBrokerHandoffContext::new(
        *owned.stable().authority_id(),
        *owned.session_id(),
        owned.launch_generation(),
        [31; 32],
    )
    .unwrap();
    let expected = context.clone();
    let (desktop, peer) = UnixStream::pair().unwrap();
    desktop
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (supervisor, registration) = prepare(fixture, desktop, case.tamper).unwrap();
    let bootstrap = supervisor
        .lock()
        .unwrap()
        .process
        .as_ref()
        .unwrap()
        .recovery_bootstrap()
        .unwrap();
    let daemon = std::thread::spawn(move || respond(peer, &owned, context, case));
    let calls = Arc::new(AtomicUsize::new(0));
    let registration = Registration {
        inner: registration,
        calls: Arc::clone(&calls),
        invalidate: case.stale.then(|| Arc::clone(&supervisor)),
    };
    let mut control = SharedControl {
        supervisor: Arc::clone(&supervisor),
        bootstrap,
        runtime: tokio::runtime::Handle::current(),
        registration,
    };
    let result = tokio::task::spawn_blocking(move || {
        let keys = runne_api::LaunchSecret::from_bytes([3; 32])
            .unwrap()
            .derive_keys();
        let auth = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        if matches!(case.reply, Reply::KillAck) {
            control.acknowledge(&expected, &auth, [7; 16])
        } else {
            control.receive(
                &auth,
                ExpectedReply {
                    context: &expected,
                    phase: ProviderCredentialBrokerHandoffFrame::PHASE_READY,
                    purpose: 1,
                    nonce: [7; 16],
                },
            )
        }
    })
    .await
    .unwrap();
    reap(&supervisor);
    drop(supervisor);
    let delivered = daemon.join().unwrap();
    assert_eq!(result.is_ok(), !case.tamper && !case.repeat && !case.stale);
    assert_eq!(delivered, !case.tamper && !case.stale);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

fn rejoin(
    keys: &ProtectedActivationKeys,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    attempt: u64,
) -> Vec<u8> {
    let enrollment = owned.enrollment_binding();
    let now = crate::protected_runtime::credential_service_session::unix_millis().unwrap();
    let binding = CredentialServiceRejoinBinding::new(
        [9; 16],
        *owned.session_id(),
        owned.launch_generation(),
        owned.launch_generation(),
        enrollment.desktop_supervisor_generation(),
        1,
        *enrollment.installation_identity_digest(),
        *enrollment.release_tuple_digest(),
        attempt,
        now + 5_000,
    )
    .unwrap();
    CredentialServiceSessionAuthenticator::from_protected_activation(keys)
        .require_rejoin(binding)
        .into_control_frame()
}

fn respond(
    mut peer: UnixStream,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    context: ProviderCredentialBrokerHandoffContext,
    case: Case,
) -> bool {
    let keys = runne_api::LaunchSecret::from_bytes([3; 32])
        .unwrap()
        .derive_keys();
    write_frame(&mut peer, &rejoin(&keys, owned, 2)).unwrap();
    let Ok(claim) = read_frame(&mut peer) else {
        return false;
    };
    let Ok(ack) = read_frame(&mut peer) else {
        return false;
    };
    let auth = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
    let verified = auth.decode_and_verify_registration(&claim[4..]).unwrap();
    let now = crate::protected_runtime::credential_service_session::unix_millis().unwrap();
    auth.decode_and_verify_ack_for(&ack[4..], verified.binding(), now)
        .unwrap();
    if case.repeat {
        write_frame(&mut peer, &rejoin(&keys, owned, 3)).unwrap();
        assert!(read_frame(&mut peer).is_err());
    } else {
        let broker = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let now = crate::MacOsContinuousClock::now_millis().unwrap();
        let offer = ProviderCredentialBrokerHandoffFrame::offer(
            context,
            if matches!(case.reply, Reply::KillAck) {
                3
            } else {
                1
            },
            now,
            now + 30_000,
            [7; 16],
            &broker,
        )
        .unwrap();
        let reply = if matches!(case.reply, Reply::KillAck) {
            offer.acknowledgement(&broker)
        } else {
            offer.ready(&broker)
        };
        write_frame(&mut peer, &reply.encode_frame()).unwrap();
    }
    true
}
