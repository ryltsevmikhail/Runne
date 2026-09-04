use super::LaunchAuthorityError;

/// Exact admitted host and rendezvous binding, without native intent material.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedCredentialRecoveryContext {
    pub(super) installation: [u8; 32],
    pub(super) release: [u8; 32],
    pub(super) session: [u8; 32],
    pub(super) daemon: [u8; 32],
    pub(super) peer: [u8; 32],
    pub(super) broker: [u8; 32],
    pub(super) database: u64,
    pub(super) supervisor: u64,
}

impl ProtectedCredentialRecoveryContext {
    /// Checks representation only; the protected host must establish these facts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation: [u8; 32],
        release: [u8; 32],
        session: [u8; 32],
        daemon: [u8; 32],
        peer: [u8; 32],
        broker: [u8; 32],
        database: u64,
        supervisor: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if [installation, release, session, daemon, peer, broker].contains(&[0; 32])
            || database == 0
            || supervisor == 0
            || database > i64::MAX as u64
            || supervisor > i64::MAX as u64
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            installation,
            release,
            session,
            daemon,
            peer,
            broker,
            database,
            supervisor,
        })
    }
}

/// Safe metadata describing one durable recovery attempt; not a store witness.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedCredentialRecoveryOffer {
    pub(super) context: ProtectedCredentialRecoveryContext,
    pub(super) operation: [u8; 16],
    pub(super) continuation: [u8; 32],
    pub(super) attempt: u64,
    pub(super) lifecycle: u64,
    pub(super) fence: u64,
    pub(super) issued: u64,
    pub(super) expires: u64,
}

impl ProtectedCredentialRecoveryOffer {
    /// Uses high-water Unix seconds and a lease of at most 300 seconds.
    /// Only the store-issued witness, not this metadata, authorizes recovery.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: ProtectedCredentialRecoveryContext,
        operation: [u8; 16],
        continuation: [u8; 32],
        attempt: u64,
        lifecycle: u64,
        fence: u64,
        issued: u64,
        expires: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if operation == [0; 16]
            || continuation == [0; 32]
            || [attempt, lifecycle, fence]
                .iter()
                .any(|v| *v == 0 || *v > i64::MAX as u64)
            || expires <= issued
            || expires > i64::MAX as u64
            || expires - issued > 300
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            context,
            operation,
            continuation,
            attempt,
            lifecycle,
            fence,
            issued,
            expires,
        })
    }

    pub(super) fn require_current(
        &self,
        context: &ProtectedCredentialRecoveryContext,
        now: u64,
    ) -> Result<(), LaunchAuthorityError> {
        if &self.context != context || now < self.issued || now >= self.expires {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(())
    }

    pub(super) fn payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(296);
        let c = &self.context;
        for digest in [
            c.installation,
            c.release,
            c.session,
            c.daemon,
            c.peer,
            c.broker,
        ] {
            bytes.extend_from_slice(&digest);
        }
        for value in [c.database, c.supervisor] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.operation);
        bytes.extend_from_slice(&self.continuation);
        for value in [
            self.attempt,
            self.lifecycle,
            self.fence,
            self.issued,
            self.expires,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes
    }

    pub(super) fn from_payload(mut bytes: &[u8]) -> Result<Self, LaunchAuthorityError> {
        if bytes.len() != 296 {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        fn take<const N: usize>(bytes: &mut &[u8]) -> [u8; N] {
            let (value, rest) = bytes.split_at(N);
            *bytes = rest;
            value.try_into().expect("fixed payload length checked")
        }
        let context = ProtectedCredentialRecoveryContext::new(
            take(&mut bytes),
            take(&mut bytes),
            take(&mut bytes),
            take(&mut bytes),
            take(&mut bytes),
            take(&mut bytes),
            u64::from_be_bytes(take(&mut bytes)),
            u64::from_be_bytes(take(&mut bytes)),
        )?;
        Self::new(
            context,
            take(&mut bytes),
            take(&mut bytes),
            u64::from_be_bytes(take(&mut bytes)),
            u64::from_be_bytes(take(&mut bytes)),
            u64::from_be_bytes(take(&mut bytes)),
            u64::from_be_bytes(take(&mut bytes)),
            u64::from_be_bytes(take(&mut bytes)),
        )
    }
}
