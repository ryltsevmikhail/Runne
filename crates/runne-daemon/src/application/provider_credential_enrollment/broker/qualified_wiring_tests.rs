//! B4–B7 wiring tests: qualified budget discipline, generic trait dispatch,
//! and the neutral admission bundle carrier. Driver-level fixture flows with
//! signed context/fault bundles and real-channel peer exchanges land with
//! the B8 driver wiring (needs retained-process fixtures).

use runne_api::ProviderCredentialEnrollmentHostError as Error;
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialSecretClaimOffer,
    CredentialSecretPublication, IssuedCredentialTicketAttempt,
};
use zeroize::Zeroizing;

use super::CredentialBrokerChannel;
use super::qualified_control::QualifiedControl;
use super::qualified_exchange::QualifiedCredentialBrokerChannel;

#[test]
fn expired_qualified_budget_fails_closed() {
    let past = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("clock");
    assert!(QualifiedControl::check_deadline(past).is_err());
}

#[test]
fn fresh_qualified_budget_remains_admitted() {
    let future = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(5))
        .expect("clock");
    assert!(QualifiedControl::check_deadline(future).is_ok());
}

/// Generic driver path: exactly how `claim_ticket_from_qualified_channel`
/// reaches a channel. Returns every closed failure the dispatched calls
/// produce; the previous UFCS bug resolved these calls to the trait itself.
fn through_traits<C: CredentialBrokerChannel + QualifiedCredentialBrokerChannel>(
    channel: &mut C,
) -> Vec<Error> {
    let _ = channel.binding_digest();
    vec![
        channel.receive().err().unwrap_or(Error::Unavailable),
        channel
            .send(Zeroizing::new(Vec::new()))
            .err()
            .unwrap_or(Error::Unavailable),
        channel
            .send_qualified_prelude()
            .err()
            .unwrap_or(Error::Unavailable),
        channel
            .receive_qualified_ack()
            .err()
            .unwrap_or(Error::Unavailable),
        channel
            .qualified_exchange_check()
            .err()
            .unwrap_or(Error::Unavailable),
    ]
}

/// Minimal fake proving generic dispatch reaches the fail-closed trait
/// defaults rather than any self-recursive resolution.
struct DenyingFakeChannel;

impl CredentialBrokerChannel for DenyingFakeChannel {
    fn binding_digest(&self) -> CredentialBindingDigest {
        CredentialBindingDigest::from_measured([1; 32]).expect("measured")
    }
    fn send_issue(
        &mut self,
        _receipt: &IssuedCredentialTicketAttempt,
        _frame: CredentialBrokerFrame,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn send(&mut self, _frame: Zeroizing<Vec<u8>>) -> Result<(), Error> {
        Err(Error::AccessDenied)
    }
    fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        Err(Error::AccessDenied)
    }
    fn sign_publication(
        &mut self,
        _offer: CredentialSecretClaimOffer,
    ) -> Result<CredentialSecretPublication, Error> {
        Err(Error::AccessDenied)
    }
}

impl QualifiedCredentialBrokerChannel for DenyingFakeChannel {}

#[test]
fn generic_dispatch_reaches_fail_closed_trait_defaults() {
    let mut channel = DenyingFakeChannel;
    let results = through_traits(&mut channel);
    assert!(
        results.iter().all(|error| *error == Error::AccessDenied),
        "dispatched calls must hit the fail-closed defaults: {results:?}"
    );
}

/// Compile-only witness: the Linux channel satisfies BOTH consolidated
/// traits, so the same generic driver reaches it (construction needs the
/// retained-process fixture added with the B8 driver wiring).
#[cfg(target_os = "linux")]
#[expect(
    dead_code,
    reason = "type-level proof only; the B8 driver constructs the channel"
)]
fn linux_channel_satisfies_both_traits(
    channel: &mut super::unix_linux::LinuxCredentialBrokerChannel,
) {
    let _ = through_traits(channel);
}
