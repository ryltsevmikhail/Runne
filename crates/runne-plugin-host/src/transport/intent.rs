/// Durable origin of a plugin-start intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStartIntentOrigin {
    /// The journal row was created by this reservation call.
    Fresh,
    /// The exact journal row already existed and must be reconciled.
    Existing,
}

/// Opaque host-created reservation for one exact process start request.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginStartIntent {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    reservation: [u8; 32],
    origin: PluginStartIntentOrigin,
}

impl PluginStartIntent {
    #[allow(dead_code)] // Called by an external durable authority implementation.
    pub(crate) fn issued(
        activation_id: PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
        reservation: [u8; 32],
    ) -> Self {
        Self::with_origin(
            activation_id,
            package_digest,
            generation,
            reservation,
            PluginStartIntentOrigin::Fresh,
        )
    }

    pub(crate) fn with_origin(
        activation_id: PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
        reservation: [u8; 32],
        origin: PluginStartIntentOrigin,
    ) -> Self {
        Self {
            activation_id,
            package_digest,
            generation,
            reservation,
            origin,
        }
    }

    pub(crate) fn matches(
        &self,
        activation_id: &PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
    ) -> bool {
        self.activation_id == *activation_id
            && self.package_digest == package_digest
            && self.generation == generation
    }

    pub(crate) const fn reservation(&self) -> &[u8; 32] {
        &self.reservation
    }

    pub(crate) const fn origin(&self) -> PluginStartIntentOrigin {
        self.origin
    }
}

/// Failure to reserve a durable plugin-start intent before crossing the process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStartIntentPortError {
    /// The durable reservation service is unavailable.
    Unavailable,
    /// An existing durable reservation conflicts with this activation.
    Conflict,
}

/// Atomic durable journal failure for a plugin-start reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStartIntentJournalError {
    /// The journal could not durably complete the operation.
    Unavailable,
    /// This activation id is already bound to different verified authority data.
    Conflict,
}

/// Durable reservation result. Existing reservations must be reconciled before
/// another start can be attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStartIntentJournalResult {
    /// This call atomically created the durable row.
    Fresh([u8; 32]),
    /// This call recovered an exact previously persisted row.
    Existing([u8; 32]),
}

/// Immutable authority binding that must be recorded before process start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStartIntentBinding {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
}

impl PluginStartIntentBinding {
    /// Creates the exact registry-verified binding for one activation.
    pub fn new(
        activation_id: PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
    ) -> Self {
        Self {
            activation_id,
            package_digest,
            generation,
        }
    }

    /// Returns the activation correlation id.
    pub fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
    }
    /// Returns the verified package digest.
    pub const fn package_digest(&self) -> PluginDigest {
        self.package_digest
    }
    /// Returns the registry generation.
    pub const fn generation(&self) -> PluginGeneration {
        self.generation
    }
}

/// Project-owned durable storage boundary for atomic start-intent reservation.
///
/// Implementations must atomically insert this exact binding or return the
/// previously stored reservation for the same binding. A reused activation id
/// with different package or generation must return `Conflict` without
/// mutation. The reservation must be non-zero and unique for distinct bindings.
pub trait PluginStartIntentJournal {
    /// Atomically reserves or looks up one binding and its opaque journal token.
    fn reserve_or_lookup(
        &self,
        binding: &PluginStartIntentBinding,
    ) -> Result<PluginStartIntentJournalResult, PluginStartIntentJournalError>;
}

/// Generic durable start-intent authority backed by a project-owned journal.
#[derive(Debug)]
pub struct DurablePluginStartIntentAuthority<J> {
    journal: J,
}

impl<J> DurablePluginStartIntentAuthority<J> {
    /// Wraps the durable journal used to persist reservations across host restart.
    pub const fn new(journal: J) -> Self {
        Self { journal }
    }

    /// Returns the wrapped journal for integration-owned lifecycle management.
    pub const fn journal(&self) -> &J {
        &self.journal
    }
}

impl<J: PluginStartIntentJournal> PluginStartIntentPort for DurablePluginStartIntentAuthority<J> {
    fn reserve(
        &self,
        activation_id: &PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
    ) -> Result<PluginStartIntent, PluginStartIntentPortError> {
        let binding =
            PluginStartIntentBinding::new(activation_id.clone(), package_digest, generation);
        let reservation =
            self.journal
                .reserve_or_lookup(&binding)
                .map_err(|error| match error {
                    PluginStartIntentJournalError::Unavailable => {
                        PluginStartIntentPortError::Unavailable
                    }
                    PluginStartIntentJournalError::Conflict => PluginStartIntentPortError::Conflict,
                })?;
        let (reservation, origin) = match reservation {
            PluginStartIntentJournalResult::Fresh(value) => (value, PluginStartIntentOrigin::Fresh),
            PluginStartIntentJournalResult::Existing(value) => {
                (value, PluginStartIntentOrigin::Existing)
            }
        };
        if reservation == [0; 32] {
            return Err(PluginStartIntentPortError::Unavailable);
        }
        Ok(PluginStartIntent::with_origin(
            activation_id.clone(),
            package_digest,
            generation,
            reservation,
            origin,
        ))
    }
}

/// Project-owned durable reservation authority. Implementations must persist
/// uniqueness across restart; this port deliberately does not expose a public
/// successful reservation constructor.
pub trait PluginStartIntentPort {
    /// Reserves one opaque, non-cloneable start intent bound to this activation.
    fn reserve(
        &self,
        activation_id: &PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
    ) -> Result<PluginStartIntent, PluginStartIntentPortError>;
}
