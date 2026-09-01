use runne_domain::DigestEqualityMatcherV1;

use super::{PendingCredentialIssueTicketV1, SignedCredentialWriterSessionAttestationV1};

impl SignedCredentialWriterSessionAttestationV1 {
    /// Compares the signed ticket claim to the exact prefetched broker frame.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_pending_issue_ticket(&self, pending: &PendingCredentialIssueTicketV1) -> bool {
        pending.matches_attested(&self.claims.ticket.issue_ticket)
    }

    /// Compares only the handoff facts observable on the inherited channel.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_handoff(
        &self,
        channel_binding: &[u8; 32],
        publication_public_key: &[u8; 32],
        handoff_digest: &[u8; 32],
    ) -> bool {
        self.channel.as_bytes() == *channel_binding
            && self.publication_public_key == *publication_public_key
            && self.claims.process.handoff.as_bytes() == *handoff_digest
    }

    /// Compares only the live writer and daemon process measurements.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_live_processes(
        &self,
        writer_start: &[u8; 32],
        writer_image: &[u8; 32],
        daemon_start: &[u8; 32],
        daemon_image: &[u8; 32],
    ) -> bool {
        self.claims.process.writer_start.as_bytes() == *writer_start
            && self.claims.process.writer_image.as_bytes() == *writer_image
            && self.claims.process.daemon_start.as_bytes() == *daemon_start
            && self.claims.process.daemon_image.as_bytes() == *daemon_image
    }

    /// Compares the provisional signed-release binding without admitting trust or time.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_provisional_release_binding(
        &self,
        release_binding: &DigestEqualityMatcherV1,
    ) -> bool {
        release_binding.matches(&self.claims.runtime.release_tuple.as_bytes())
    }

    /// Projects the signed release binding as an opaque equality expectation.
    #[doc(hidden)]
    #[must_use]
    pub fn release_binding_expectation(&self) -> DigestEqualityMatcherV1 {
        DigestEqualityMatcherV1::from_expected(self.claims.runtime.release_tuple.as_bytes())
    }

    /// Checks the signed one-shot window against the process wall clock.
    #[doc(hidden)]
    #[must_use]
    pub fn is_current_now(&self) -> bool {
        let Ok(elapsed) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
            return false;
        };
        let Ok(now) = i64::try_from(elapsed.as_secs()) else {
            return false;
        };
        is_current_window(
            self.claims.ticket.issued_at,
            self.claims.ticket.expires_at,
            now,
        )
    }
}

fn is_current_window(issued_at: i64, expires_at: i64, now: i64) -> bool {
    issued_at <= now && now < expires_at
}

#[cfg(test)]
#[path = "matchers_tests.rs"]
mod tests;
