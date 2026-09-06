use super::*;
use crate::protected_activation::{CredentialServiceRuntimeGateway, control_v3::with_control};
use runne_api::{
    ProtectedCredentialEnrollmentLifecycleCodec as Codec,
    ProviderCredentialEnrollmentHostError as HostError,
};
use runne_provider::{CredentialEnrollmentAuthorityPair, CredentialServiceEpoch};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn gateway_readback_rejoin_reaches_desktop_terminal_without_self_wait() {
    for tamper in [false, true] {
        let fixture = runne_platform_desktop::test_only_ready_v3_enrollment_supervisor();
        let parent_expiry = fixture.credential_service_parent_expiry();
        let owned = fixture.owned_launch().unwrap();
        let (desktop, peer) = UnixStream::pair().unwrap();
        desktop
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut peer = ProtectedActivationChannel::new(peer).unwrap();
        let (authority, _) = CredentialEnrollmentAuthorityPair::new().split();
        let gateway = Arc::new(CredentialServiceRuntimeGateway::new(
            authority,
            tokio::runtime::Handle::current(),
        ));
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let daemon = std::thread::spawn(move || -> Result<(), LaunchAuthorityError> {
            let keys = runne_api::LaunchSecret::from_bytes([3; 32])
                .unwrap()
                .derive_keys();
            let codec = Codec::from_protected_activation(&keys);
            codec.decode_desktop_relay_ack(&peer.read_control_frame()?, 1, &[7; 388])?;
            let completed = with_control(
                || {
                    gateway
                        .retry_metadata_after_rejoin(|| {
                            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                                (
                                    Err(HostError::Unavailable),
                                    Some(CredentialServiceEpoch::from_bytes([9; 16]).unwrap()),
                                )
                            } else {
                                (Ok(terminal()), None)
                            }
                        })
                        .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)
                },
                || {
                    let Some(request) = gateway
                        .take_rejoin_request()
                        .map_err(|_| LaunchAuthorityError::InvalidContract)?
                    else {
                        return Ok(());
                    };
                    let registered = register(&mut peer, &keys, &owned, parent_expiry);
                    gateway
                        .complete_rejoin(request, registered.is_ok())
                        .map_err(|_| LaunchAuthorityError::InvalidContract)?;
                    registered
                },
            )?;
            peer.write_control_frame(&codec.encode_daemon_snapshot(&completed, 3)?)?;
            Ok(())
        });
        let result =
            runne_platform_desktop::test_only_pair_terminal(fixture, desktop, tamper).await;
        let receipt = daemon.join().unwrap();
        if tamper {
            assert!(result.is_err() && receipt.is_err());
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        } else {
            assert_eq!(result.unwrap(), terminal());
            receipt.unwrap();
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
        }
    }
}

fn register(
    peer: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    parent_expiry: u64,
) -> Result<(), LaunchAuthorityError> {
    let started = now()?;
    let enrollment = owned.enrollment_binding();
    let binding = CredentialServiceRejoinBinding::new(
        [9; 16],
        *owned.session_id(),
        owned.launch_generation(),
        owned.launch_generation(),
        enrollment.desktop_supervisor_generation(),
        1,
        *enrollment.installation_identity_digest(),
        *enrollment.release_tuple_digest(),
        2,
        started + 5_000,
    )
    .unwrap();
    peer.write_control_frame(
        &CredentialServiceSessionAuthenticator::from_protected_activation(keys)
            .require_rejoin(binding.clone())
            .into_control_frame(),
    )?;
    let received = receive(
        peer,
        keys,
        &ExpectedCredentialServiceRegistration::from_rejoin(&binding, parent_expiry),
        started,
        interleaved::receive,
        now,
    )?;
    assert!(
        received.deferred.is_none(),
        "terminal wait must not replay relay ACK"
    );
    assert_eq!(received.session.binding().join_attempt(), 2);
    Ok(())
}

fn terminal() -> runne_api::ProviderCredentialOperationSnapshotV2 {
    runne_api::ProviderCredentialOperationSnapshotV2::new(
        runne_api::ProviderCredentialOperationHandleV2::from_bytes([1; 48]).unwrap(),
        None,
        runne_api::ProviderCredentialProviderV2::OpenAi,
        runne_api::ProviderCredentialOperationKindV2::Pair,
        runne_api::ProviderCredentialOperationStateV2::Completed,
        1,
        1,
        false,
        None,
    )
    .unwrap()
}
