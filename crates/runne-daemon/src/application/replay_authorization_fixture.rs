//! Test-support construction of the production replay authorization so
//! integration suites exercise the real NM-06 delivery gate (trust re-check)
//! instead of a stand-in authorizer. Not part of the production surface.

#[cfg(feature = "test-support")]
mod imp {
    use std::sync::{Arc, Mutex};

    use runne_application::local_session::LocalSessionService;
    use runne_application::ports::ReplayAuthorizationPort;
    use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
    use runne_store::store::StoreTransaction;

    use super::super::replay_authorization::DaemonReplayAuthorization;
    use super::super::trust_delivery::DeliveryTrustGate;

    pub fn with_trust(
        replay_authority_id: [u8; 16],
        local_session: Arc<Mutex<LocalSessionService>>,
        authority: Arc<ProjectTrustPolicyAuthority>,
        store: &StoreTransaction,
    ) -> Arc<dyn ReplayAuthorizationPort> {
        Arc::new(DaemonReplayAuthorization::new(
            replay_authority_id,
            local_session,
            Some(DeliveryTrustGate::open(authority, store)),
        ))
    }

    pub fn closed(
        replay_authority_id: [u8; 16],
        local_session: Arc<Mutex<LocalSessionService>>,
    ) -> Arc<dyn ReplayAuthorizationPort> {
        Arc::new(DaemonReplayAuthorization::new(
            replay_authority_id,
            local_session,
            Some(DeliveryTrustGate::closed()),
        ))
    }
}

#[cfg(feature = "test-support")]
pub use imp::{closed, with_trust};
