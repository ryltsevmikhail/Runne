use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use rand::RngCore as _;
use runne_api::{
    BootstrapAck, BootstrapControlReply, BootstrapControlRequest, DesktopOffer,
    RuntimeBootstrapRequest,
};
use runne_macos_xpc::{QualificationRunnerRequest, QualificationRunnerXpcClient};
use zeroize::Zeroizing;

use super::VerifiedInstalledQualificationBootstrapCandidate;

const ACTIVATION_LIMIT: Duration = Duration::from_secs(30);
const FIRST_ACTIVATION_RESERVE: Duration = Duration::from_secs(10);

#[path = "acknowledgement/run_transport.rs"]
mod run_transport;
pub use run_transport::VerifiedQualificationRunTransport;

/// Retained, peer-verified acknowledgement of the exact bootstrap exchange.
///
/// This receipt grants no runtime, credential, or qualification case authority.
/// The daemon must independently select its fixed scoped profile before using it.
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedRuntimeQualificationAcknowledgement;
/// let _ = VerifiedRuntimeQualificationAcknowledgement {};
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedRuntimeQualificationAcknowledgement;
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<VerifiedRuntimeQualificationAcknowledgement>();
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedRuntimeQualificationAcknowledgement;
/// fn needs_wire<T: serde::Serialize>() {}
/// needs_wire::<VerifiedRuntimeQualificationAcknowledgement>();
/// ```
pub struct VerifiedRuntimeQualificationAcknowledgement {
    candidate: VerifiedInstalledQualificationBootstrapCandidate,
    client: QualificationRunnerXpcClient,
    offer: DesktopOffer,
    acknowledgement: BootstrapAck,
    challenge: [u8; 32],
    deadline: Instant,
    run_expiry: Instant,
}

impl VerifiedInstalledQualificationBootstrapCandidate {
    /// Exchanges one candidate-bound request on the fixed runtime bootstrap endpoint.
    /// Any failure burns the connection and does not permit ordinary launch fallback.
    #[must_use]
    pub async fn receive_bootstrap_acknowledgement(
        self,
        offer: DesktopOffer,
        desktop_channel: &UnixStream,
        inherited_deadline: Instant,
    ) -> Option<VerifiedRuntimeQualificationAcknowledgement> {
        let observed_at = Instant::now();
        let observed_wall = super::now()?;
        let deadline = offer_deadline(&offer, observed_wall, inherited_deadline, observed_at)?;
        let run_expiry = signed_run_expiry(offer.run_not_after(), observed_wall, observed_at)?;
        let candidate = self.confirm_bootstrap_binding(desktop_channel, offer.binding())?;
        let (candidate, configuration) = candidate.prepare_bootstrap_transport(desktop_channel)?;
        let mut challenge = [0; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut challenge).ok()?;
        let request = RuntimeBootstrapRequest::new(
            offer.offer_id(),
            challenge,
            candidate.candidate_sha256()?,
            candidate.raw_v3_tuple_sha256()?,
            offer.binding().profile_sha256(),
        )
        .ok()?;
        let bytes = BootstrapControlRequest::RuntimeBootstrap(request)
            .encode()
            .ok()?;
        let request = QualificationRunnerRequest::from_zeroizing(Zeroizing::new(bytes)).ok()?;
        let exchange_deadline = deadline.checked_sub(FIRST_ACTIVATION_RESERVE)?;
        (Instant::now() < exchange_deadline).then_some(())?;
        let client = QualificationRunnerXpcClient::connect_bootstrap(&configuration).ok()?;
        let reply = client.exchange(request, exchange_deadline).await.ok()?;
        let BootstrapControlReply::BootstrapAck(acknowledgement) =
            BootstrapControlReply::decode(&reply.into_zeroizing()).ok()?
        else {
            return None;
        };
        matches_acknowledgement(&offer, &acknowledgement, challenge).then_some(())?;
        VerifiedRuntimeQualificationAcknowledgement {
            candidate,
            client,
            offer,
            acknowledgement,
            challenge,
            deadline,
            run_expiry,
        }
        .revalidate(desktop_channel)
    }
}

impl VerifiedRuntimeQualificationAcknowledgement {
    /// Returns authenticated binding claims, never profile or mutation authority.
    #[must_use]
    pub const fn binding(&self) -> &runne_api::RunBinding {
        self.acknowledgement.binding()
    }

    /// Rechecks the same peer, current desktop, package, journals, and deadline.
    #[must_use]
    pub fn revalidate(self, desktop_channel: &UnixStream) -> Option<Self> {
        let Self {
            candidate,
            client,
            offer,
            acknowledgement,
            challenge,
            deadline,
            run_expiry,
        } = self;
        let observed_at = Instant::now();
        let deadline = offer_deadline(&offer, super::now()?, deadline, observed_at)?;
        matches_acknowledgement(&offer, &acknowledgement, challenge).then_some(())?;
        client.revalidate_peer(deadline).ok()?;
        let candidate = candidate.confirm_bootstrap_binding(desktop_channel, offer.binding())?;
        client.revalidate_peer(deadline).ok()?;
        let observed_at = Instant::now();
        let deadline = offer_deadline(&offer, super::now()?, deadline, observed_at)?;
        let run_expiry = run_expiry.min(signed_run_expiry(
            offer.run_not_after(),
            super::now()?,
            observed_at,
        )?);
        (Instant::now() < run_expiry).then_some(())?;
        Some(Self {
            candidate,
            client,
            offer,
            acknowledgement,
            challenge,
            deadline,
            run_expiry,
        })
    }
}

fn matches_acknowledgement(offer: &DesktopOffer, ack: &BootstrapAck, challenge: [u8; 32]) -> bool {
    let expected = offer.binding();
    let actual = ack.binding();
    ack.offer_id() == offer.offer_id()
        && ack.daemon_challenge() == challenge
        && ack.run_not_after() == offer.run_not_after()
        && actual.workflow_run_id() == expected.workflow_run_id()
        && actual.source_revision() == expected.source_revision()
        && actual.candidate_sha256() == expected.candidate_sha256()
        && actual.raw_v3_tuple_sha256() == expected.raw_v3_tuple_sha256()
        && actual.namespace_sha256() == expected.namespace_sha256()
        && actual.manifest_sha256() == expected.manifest_sha256()
        && actual.profile_sha256() == expected.profile_sha256()
}

fn offer_deadline(
    offer: &DesktopOffer,
    now: u64,
    inherited: Instant,
    observed_at: Instant,
) -> Option<Instant> {
    let remaining = offer
        .expires_at()
        .min(offer.run_not_after())
        .checked_sub(now)?;
    (remaining > 0).then_some(())?;
    let deadline = inherited
        .min(observed_at.checked_add(ACTIVATION_LIMIT)?)
        .min(observed_at.checked_add(Duration::from_secs(remaining))?);
    (Instant::now() < deadline).then_some(deadline)
}

fn signed_run_expiry(run_not_after: u64, wall_now: u64, observed_at: Instant) -> Option<Instant> {
    let remaining = run_not_after.checked_sub(wall_now)?;
    (remaining > 0).then_some(())?;
    observed_at.checked_add(Duration::from_secs(remaining))
}

#[cfg(test)]
#[path = "acknowledgement/tests.rs"]
mod tests;
