//! Consuming transition from a fresh bootstrap receipt to bounded transport.

#[cfg(test)]
use super::signed_run_expiry;
use super::{
    BootstrapAck, Duration, Instant, QualificationRunnerXpcClient, UnixStream,
    VerifiedInstalledQualificationBootstrapCandidate, VerifiedRuntimeQualificationAcknowledgement,
};

const RUN_TRANSPORT_LIMIT: Duration = Duration::from_mins(15);

/// Retained transport for the same authenticated qualification connection.
///
/// This type grants no profile, case, credential, database, or launch authority.
/// In particular, retaining the connection does not qualify the installed release.
/// A future case dispatcher must independently validate its scoped profile and
/// one-use case authority; no raw client or exchange API is exposed here.
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedQualificationRunTransport;
/// let _ = VerifiedQualificationRunTransport {};
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedQualificationRunTransport;
/// fn cloneable<T: Clone>() {}
/// cloneable::<VerifiedQualificationRunTransport>();
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedQualificationRunTransport;
/// fn serializable<T: serde::Serialize>() {}
/// serializable::<VerifiedQualificationRunTransport>();
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedQualificationRunTransport;
/// fn escape(lease: VerifiedQualificationRunTransport) { let _ = lease.client; }
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::{VerifiedQualificationRunTransport, VerifiedInstalledEnrollmentCapability};
/// fn promote(lease: VerifiedQualificationRunTransport) -> VerifiedInstalledEnrollmentCapability {
///     lease.into()
/// }
/// ```
pub struct VerifiedQualificationRunTransport {
    candidate: VerifiedInstalledQualificationBootstrapCandidate,
    client: QualificationRunnerXpcClient,
    acknowledgement: BootstrapAck,
    deadline: Instant,
}

impl VerifiedRuntimeQualificationAcknowledgement {
    /// Consumes a still-fresh ACK, rechecking its original activation deadline.
    ///
    /// Only this one-way transition may retain transport beyond offer expiry.
    /// It is bounded by the signed run expiry and an independent fifteen-minute
    /// cap, and does not extend the activation budget of the consumed receipt.
    #[must_use]
    pub fn into_run_transport(
        self,
        desktop_channel: &UnixStream,
    ) -> Option<VerifiedQualificationRunTransport> {
        let fresh = self.revalidate(desktop_channel)?;
        let monotonic_now = Instant::now();
        let wall_now = super::super::now()?;
        let deadline = transition_deadline(
            fresh.deadline,
            fresh.run_expiry,
            fresh.acknowledgement.run_not_after(),
            wall_now,
            monotonic_now,
        )?;
        Some(VerifiedQualificationRunTransport {
            candidate: fresh.candidate,
            client: fresh.client,
            acknowledgement: fresh.acknowledgement,
            deadline,
        })
    }
}

impl VerifiedQualificationRunTransport {
    /// Authenticated claims only; the profile digest is not selected authority.
    #[must_use]
    pub const fn binding(&self) -> &runne_api::RunBinding {
        self.acknowledgement.binding()
    }

    /// Rechecks the same connection, desktop peer, artifacts, and run expiry.
    /// Failure consumes and drops the retained connection without reopening it.
    #[must_use]
    pub fn revalidate(self, desktop_channel: &UnixStream) -> Option<Self> {
        let Self {
            candidate,
            client,
            acknowledgement,
            deadline,
        } = self;
        let observed_at = Instant::now();
        let deadline = run_deadline(
            acknowledgement.run_not_after(),
            super::super::now()?,
            observed_at,
            Some(deadline),
        )?;
        client.revalidate_peer(deadline).ok()?;
        let candidate =
            candidate.confirm_bootstrap_binding(desktop_channel, acknowledgement.binding())?;
        client.revalidate_peer(deadline).ok()?;
        let observed_at = Instant::now();
        let deadline = run_deadline(
            acknowledgement.run_not_after(),
            super::super::now()?,
            observed_at,
            Some(deadline),
        )?;
        Some(Self {
            candidate,
            client,
            acknowledgement,
            deadline,
        })
    }
}

fn transition_deadline(
    activation_deadline: Instant,
    retained_run_expiry: Instant,
    run_not_after: u64,
    wall_now: u64,
    monotonic_now: Instant,
) -> Option<Instant> {
    (monotonic_now < activation_deadline).then_some(())?;
    run_deadline(
        run_not_after,
        wall_now,
        monotonic_now,
        Some(retained_run_expiry),
    )
}

fn run_deadline(
    run_not_after: u64,
    wall_now: u64,
    monotonic_now: Instant,
    retained: Option<Instant>,
) -> Option<Instant> {
    let remaining = run_not_after.checked_sub(wall_now)?;
    (remaining > 0).then_some(())?;
    let deadline = monotonic_now
        .checked_add(Duration::from_secs(remaining))?
        .min(monotonic_now.checked_add(RUN_TRANSPORT_LIMIT)?);
    let deadline = retained.map_or(deadline, |previous| previous.min(deadline));
    (monotonic_now < deadline).then_some(deadline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_rejects_expired_activation_even_with_fresh_signed_run() {
        let now = Instant::now();
        let expiry = now + Duration::from_secs(1900);
        assert!(transition_deadline(now, expiry, 2000, 100, now).is_none());
        assert!(
            transition_deadline(now, expiry, 2000, 100, now + Duration::from_secs(1)).is_none()
        );
        assert_eq!(
            transition_deadline(now + Duration::from_secs(1), expiry, 2000, 100, now),
            Some(now + RUN_TRANSPORT_LIMIT)
        );
    }

    #[test]
    fn rollback_between_ack_and_consume_cannot_extend_signed_expiry() {
        let received_at = Instant::now();
        let expiry = signed_run_expiry(120, 100, received_at).unwrap();
        let activation = received_at + Duration::from_secs(30);
        assert_eq!(
            transition_deadline(
                activation,
                expiry,
                120,
                50,
                received_at + Duration::from_secs(5)
            ),
            Some(expiry)
        );
        assert!(transition_deadline(activation, expiry, 120, 50, expiry).is_none());
    }

    #[test]
    fn signed_expiry_and_independent_cap_both_bound_transport() {
        let now = Instant::now();
        assert_eq!(
            run_deadline(200, 100, now, None),
            Some(now + Duration::from_secs(100))
        );
        assert_eq!(
            run_deadline(2000, 100, now, None),
            Some(now + RUN_TRANSPORT_LIMIT)
        );
        assert!(run_deadline(100, 100, now, None).is_none());
        assert!(run_deadline(99, 100, now, None).is_none());
    }

    #[test]
    fn revalidation_never_renews_a_lease_or_revives_expiry() {
        let now = Instant::now();
        let first = run_deadline(2000, 100, now, None).unwrap();
        assert_eq!(
            run_deadline(2000, 50, now + Duration::from_secs(10), Some(first)),
            Some(first)
        );
        assert!(run_deadline(2000, 50, first, Some(first)).is_none());
        assert_eq!(
            run_deadline(2000, 1999, now, Some(first)),
            Some(now + Duration::from_secs(1))
        );
    }
}
