use std::time::{Duration, Instant};

use rand::RngCore as _;
use runne_api::{
    BootstrapControlReply, BootstrapControlRequest, DesktopOffer, DesktopOfferRequest, RunBinding,
};
use runne_macos_xpc::{
    QualificationRunnerReply, QualificationRunnerRequest, QualificationRunnerXpcClient,
};
use zeroize::Zeroizing;

use super::VerifiedInstalledQualificationBootstrapDesktop;

#[path = "offer/preparation.rs"]
mod preparation;
pub use preparation::PreparedDesktopQualificationRun;

const OFFER_EXCHANGE_LIMIT: Duration = Duration::from_mins(15);

/// Opaque desktop offer retained with the admitted package and XPC connection.
///
/// It grants no ordinary runtime or credential authority.
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedDesktopQualificationOffer;
/// let _ = VerifiedDesktopQualificationOffer {};
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedDesktopQualificationOffer;
/// fn clone_required<T: Clone>() {}
/// clone_required::<VerifiedDesktopQualificationOffer>();
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedDesktopQualificationOffer;
/// fn wire_required<T: serde::Serialize>() {}
/// wire_required::<VerifiedDesktopQualificationOffer>();
/// ```
pub struct VerifiedDesktopQualificationOffer {
    desktop: VerifiedInstalledQualificationBootstrapDesktop,
    client: QualificationRunnerXpcClient,
    offer: DesktopOffer,
    deadline: Instant,
}

impl VerifiedInstalledQualificationBootstrapDesktop {
    /// Receives one fresh, challenge-bound desktop offer on the fixed endpoint.
    #[must_use]
    pub async fn receive_bootstrap_offer(self) -> Option<VerifiedDesktopQualificationOffer> {
        let (desktop, configuration) = self.prepare_bootstrap_transport()?;
        let deadline = Instant::now().checked_add(OFFER_EXCHANGE_LIMIT)?;
        let client = QualificationRunnerXpcClient::connect_bootstrap(&configuration).ok()?;
        let mut challenge = [0; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut challenge).ok()?;
        let request = DesktopOfferRequest::new(challenge).ok()?;
        let request = BootstrapControlRequest::DesktopOffer(request)
            .encode()
            .ok()?;
        let request = QualificationRunnerRequest::from_zeroizing(Zeroizing::new(request)).ok()?;
        let reply = client.exchange(request, deadline).await.ok()?;
        let offer = decode_offer(reply)?;
        let deadline = validate_offer(challenge, &offer, super::now()?, deadline)?;
        let desktop = desktop.confirm_bootstrap_binding(offer.binding())?;
        VerifiedDesktopQualificationOffer {
            desktop,
            client,
            offer,
            deadline,
        }
        .revalidate()
    }
}

impl VerifiedDesktopQualificationOffer {
    /// Returns the immutable run binding after installed-admission confirmation.
    #[must_use]
    pub const fn binding(&self) -> &RunBinding {
        self.offer.binding()
    }

    /// Revalidates the retained peer, installed desktop admission, and offer deadline.
    #[must_use]
    pub fn revalidate(self) -> Option<Self> {
        let Self {
            desktop,
            client,
            offer,
            deadline,
        } = self;
        let deadline = validate_offer_deadline(&offer, super::now()?, deadline)?;
        client.revalidate_peer(deadline).ok()?;
        let desktop = desktop
            .revalidate()?
            .confirm_bootstrap_binding(offer.binding())?;
        client.revalidate_peer(deadline).ok()?;
        let deadline = validate_offer_deadline(&offer, super::now()?, deadline)?;
        Some(Self {
            desktop,
            client,
            offer,
            deadline,
        })
    }
}

fn decode_offer(reply: QualificationRunnerReply) -> Option<DesktopOffer> {
    match BootstrapControlReply::decode(&reply.into_zeroizing()).ok()? {
        BootstrapControlReply::DesktopOffer(offer) => Some(offer),
        _ => None,
    }
}

fn validate_offer(
    challenge: [u8; 32],
    offer: &DesktopOffer,
    now: u64,
    cap: Instant,
) -> Option<Instant> {
    (offer.desktop_challenge() == challenge).then_some(())?;
    validate_offer_deadline(offer, now, cap)
}

fn validate_offer_deadline(offer: &DesktopOffer, now: u64, cap: Instant) -> Option<Instant> {
    let remaining = offer
        .expires_at()
        .checked_sub(now)
        .filter(|value| *value > 0)?
        .min(
            offer
                .run_not_after()
                .checked_sub(now)
                .filter(|value| *value > 0)?,
        );
    let offer_deadline = Instant::now().checked_add(Duration::from_secs(remaining))?;
    let deadline = cap.min(offer_deadline);
    (Instant::now() < deadline).then_some(deadline)
}

#[cfg(test)]
#[path = "offer/tests.rs"]
mod tests;
