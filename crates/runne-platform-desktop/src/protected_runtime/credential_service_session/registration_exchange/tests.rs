use super::*;
use runne_platform_ports::credential_service::{
    CredentialServiceDesktopReply, CredentialServicePortFuture,
};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct ClockedPeer {
    now: AtomicU64,
    after_challenge: u64,
    after_ack: u64,
    registrations: AtomicUsize,
    parent_expiry: u64,
}

#[tokio::test]
async fn rejoin_exchange_deadline_is_separate_from_installed_expiry() {
    for (after_challenge, after_ack, parent_expiry, accepted, registrations) in [
        (100, 101, 480_100, true, 1),
        (5_099, 5_099, 480_100, true, 1),
        (5_100, 5_100, 480_100, false, 0),
        (100, 5_100, 480_100, false, 1),
        (100, 1_999, 2_000, true, 1),
        (100, 2_000, 2_000, false, 1),
    ] {
        let peer = ClockedPeer {
            now: AtomicU64::new(100),
            after_challenge,
            after_ack,
            registrations: AtomicUsize::new(0),
            parent_expiry,
        };
        let mut session = [1; 16];
        session[6] = 0x70;
        session[8] = 0x80;
        let mut facts = CredentialServiceRegistrationFacts::new(
            session,
            1,
            1,
            1,
            1,
            [3; 32],
            [4; 32],
            2,
            parent_expiry,
        )
        .unwrap();
        facts.exchange_deadline = Some(5_100.min(parent_expiry));
        let keys = runne_api::LaunchSecret::from_bytes([7; 32])
            .unwrap()
            .derive_keys();
        let auth = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
        let result =
            register_with_clock(&peer, auth, facts, || Ok(peer.now.load(Ordering::SeqCst))).await;
        assert_eq!(result.is_ok(), accepted);
        assert_eq!(peer.registrations.load(Ordering::SeqCst), registrations);
        if let Ok(registered) = result {
            assert_eq!(
                registered.claim.binding().expires_at_unix_millis(),
                parent_expiry
            );
            assert_eq!(registered.exchange_deadline, Some(5_100.min(parent_expiry)));
        }
    }
}

impl CredentialServiceDesktopPort for ClockedPeer {
    fn challenge(
        &self,
        _: CredentialServiceDesktopRequest,
        _: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply> {
        Box::pin(async move {
            self.now.store(self.after_challenge, Ordering::SeqCst);
            let reply = CredentialServiceProtocolCodec::encode_reply(
                CredentialServiceRequest::RegistrationChallenge.context(),
                CredentialServiceReply::RegistrationChallenge {
                    epoch: runne_provider::CredentialServiceEpoch::from_bytes([9; 16]).unwrap(),
                    nonce: [6; 16],
                },
            )
            .unwrap();
            CredentialServiceDesktopReply::from_zeroizing(reply.into_transport_bytes())
        })
    }

    fn register(
        &self,
        request: CredentialServiceDesktopRequest,
        _: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply> {
        Box::pin(async move {
            self.registrations.fetch_add(1, Ordering::SeqCst);
            let now = self.now.load(Ordering::SeqCst);
            let registration = request
                .with_bytes(|bytes| {
                    CredentialServiceSessionAuthenticator::accept_registration_install_with_policy(
                        bytes,
                        now,
                        |binding| {
                            assert_eq!(binding.expires_at_unix_millis(), self.parent_expiry);
                            Ok(())
                        },
                    )
                })
                .unwrap();
            let (_, ack) = registration.complete(now).unwrap();
            self.now.store(self.after_ack, Ordering::SeqCst);
            CredentialServiceDesktopReply::from_zeroizing(zeroize::Zeroizing::new(ack.into_bytes()))
        })
    }
}
