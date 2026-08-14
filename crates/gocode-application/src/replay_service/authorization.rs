/// Synchronous pre-commit check for the exact replay delivery a transport will
/// serialize. Implementations must fail closed when classification is
/// unavailable.
pub trait ReplayDeliveryPrecommitGuard: Send + Sync {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError>;

    /// Checks one live event immediately before it becomes eligible for delivery.
    fn inspect_event(
        &self,
        session: &ReplaySession,
        event: &ReplayEvent,
    ) -> Result<(), ReplayError> {
        self.inspect(session, std::slice::from_ref(event))
    }

    /// Checks an acknowledgement immediately before durable cursor mutation.
    fn inspect_ack(&self, _session: &ReplaySession) -> Result<(), ReplayError> {
        Ok(())
    }

    /// Runs one durable acknowledgement/session-state mutation while the
    /// current authority remains fenced.
    fn mutate_ack(
        &self,
        session: &ReplaySession,
        mutation: &mut dyn FnMut() -> Result<usize, ReplayError>,
    ) -> Result<usize, ReplayError> {
        self.inspect_ack(session)?;
        mutation()
    }

    /// Fences one session INSERT plus its exact readback and commit.
    fn mutate_session_admission(
        &self,
        session: &ReplaySession,
        events: &[ReplayEvent],
        mutation: &mut dyn FnMut() -> Result<ReplaySession, ReplayError>,
    ) -> Result<ReplaySession, ReplayError> {
        self.inspect(session, events)?;
        mutation()
    }
}

/// Inputs used to acquire a current replay authorization lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayAuthorizationRequest {
    pub principal_id: String,
    pub authority_id: [u8; 16],
    pub session_generation: i64,
    pub expected_epoch: i64,
    pub session_id: Option<[u8; 16]>,
    pub scope: Option<ReplayScope>,
}

/// Current authorization values that may fence exactly one replay operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayAuthorizationLease {
    principal_id: String,
    authorization_epoch: i64,
    sensitivity_ceiling: Sensitivity,
}

impl ReplayAuthorizationLease {
    pub fn new(
        principal_id: impl Into<String>,
        authorization_epoch: i64,
        sensitivity_ceiling: Sensitivity,
    ) -> Result<Self, ReplayError> {
        let principal_id = principal_id.into();
        if principal_id.is_empty() || authorization_epoch < 0 {
            return Err(ReplayError::AuthorizationRevoked);
        }
        Ok(Self {
            principal_id,
            authorization_epoch,
            sensitivity_ceiling,
        })
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub const fn authorization_epoch(&self) -> i64 {
        self.authorization_epoch
    }

    pub const fn sensitivity_ceiling(&self) -> Sensitivity {
        self.sensitivity_ceiling
    }
}

/// Current authorization authority for replay open/page/ack/live operations.
pub trait ReplayAuthorizationPort: Send + Sync {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError>;

    /// Runs one mutation under the strongest fence this authority can provide.
    ///
    /// Implementations backed by an in-memory or transactional authority must
    /// hold that authority's lock through `mutation`; the default preserves the
    /// existing fail-closed revalidation contract for stateless test ports.
    fn mutate_with_current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
        mutation: &mut dyn FnMut(&ReplayAuthorizationLease) -> Result<usize, ReplayError>,
    ) -> Result<usize, ReplayError> {
        let lease = self.current_lease(request)?;
        mutation(&lease)
    }

    fn mutate_session_admission(
        &self,
        request: &ReplayAuthorizationRequest,
        mutation: &mut dyn FnMut(&ReplayAuthorizationLease) -> Result<ReplaySession, ReplayError>,
    ) -> Result<ReplaySession, ReplayError> {
        let mut result = None;
        self.mutate_with_current_lease(request, &mut |lease| {
            result = Some(mutation(lease)?);
            Ok(1)
        })?;
        result.ok_or_else(|| ReplayError::Integrity("session admission mutation did not run".to_owned()))
    }
}
