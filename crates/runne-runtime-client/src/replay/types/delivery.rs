/// Whether a validated identity is new or an exact inclusive redelivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDeliveryDisposition {
    New,
    Duplicate,
}

/// Delivery exposed only after strict binding, schema and identity validation.
#[derive(Clone, Eq, PartialEq)]
pub struct ReplayDelivery {
    pub(super) event: CanonicalReplayEvent,
    pub(super) cursor: ReplayCursor,
    pub(super) disposition: ReplayDeliveryDisposition,
    pub(super) session_id: ReplaySessionId,
}

/// Borrowed native-persistence handoff for one fully validated delivery.
///
/// The handoff exists only for the duration of [`ReplayDelivery::persist_with`].
/// It is deliberately not serializable and does not make the opaque cursor
/// wrapper constructible or encodable.
pub struct ReplayPersistenceHandoff<'a> {
    cursor_value: &'a str,
    canonical_event_bytes: &'a [u8],
    event_digest: String,
}

impl ReplayPersistenceHandoff<'_> {
    /// Returns the server-issued opaque cursor value for native durable storage.
    #[must_use]
    pub const fn cursor_value(&self) -> &str {
        self.cursor_value
    }

    /// Returns the exact stable canonical bytes validated by runne-runtime-client.
    #[must_use]
    pub const fn canonical_event_bytes(&self) -> &[u8] {
        self.canonical_event_bytes
    }

    /// Returns the lower-hex SHA-256 of the exact canonical event bytes.
    #[must_use]
    pub fn event_digest(&self) -> &str {
        &self.event_digest
    }
}

/// Stable native replay binding derived only from authenticated durable
/// runtime identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayPersistenceBinding {
    pub(super) digest: String,
}

/// Computes the lower-hex SHA-256 used by native replay persistence.
#[must_use]
pub fn replay_persistence_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

impl ReplayPersistenceBinding {
    /// Returns the domain-separated lower-hex 32-byte binding digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl fmt::Debug for ReplayDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayDelivery")
            .field("event", &self.event)
            .field("cursor", &"[opaque]")
            .field("disposition", &self.disposition)
            .field("session_id", &"[opaque]")
            .finish()
    }
}

impl ReplayDelivery {
    #[must_use]
    pub const fn event(&self) -> &CanonicalReplayEvent {
        &self.event
    }

    #[must_use]
    pub const fn event_id(&self) -> CanonicalId {
        self.event.event_id()
    }

    #[must_use]
    pub const fn cursor(&self) -> &ReplayCursor {
        &self.cursor
    }

    #[must_use]
    pub const fn canonical_digest(&self) -> &[u8; 32] {
        self.event.canonical_digest()
    }

    #[must_use]
    pub const fn disposition(&self) -> ReplayDeliveryDisposition {
        self.disposition
    }

    /// Borrows the dedicated native-persistence representation.
    ///
    /// The callback cannot retain the borrow and the cursor remains unavailable
    /// through the general-purpose [`ReplayCursor`] API.
    pub fn persist_with<T>(&self, persist: impl FnOnce(ReplayPersistenceHandoff<'_>) -> T) -> T {
        persist(ReplayPersistenceHandoff {
            cursor_value: wire::cursor_value(&self.cursor),
            canonical_event_bytes: &self.event.canonical_bytes,
            event_digest: hex::encode(self.event.canonical_digest),
        })
    }
}
