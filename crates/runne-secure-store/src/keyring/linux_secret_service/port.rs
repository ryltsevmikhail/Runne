//! Injected Secret Service bus boundary for the Linux facade.
//!
//! The port deliberately exposes NO prompt and NO unlock operations: dispatch
//! and enrollment paths that use this facade cannot invoke them by
//! construction (DESIGN v6 §4-P3/F1′; tests T3/T9 pin this at the type level).
//! Every method takes the resolved owner unique name as destination.

use super::dh_session::WireSecret;

/// Minimal transport-level error for the injected bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsBusError {
    /// Connection/serialization/peer failure (includes peer death mid-call).
    Transport,
}

/// Owner-uniqueness facts of one bus peer connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
}

/// Result of one service-wide attribute search.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SsSearchOutcome {
    pub unlocked: Vec<String>,
    pub locked: Vec<String>,
}

/// Outcome of a mutation whose service side may need a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsMutationOutcome {
    /// Completed without any prompt object.
    Done,
    /// The service returned a prompt object; the facade never executes it.
    PromptRequired,
}

/// The injected Secret Service transport. No prompt/unlock surface exists.
pub trait SecretServiceBus {
    /// `GetNameOwner` on the bus daemon: current owner of a well-known name,
    /// `None` when unowned (never activates the name).
    fn name_owner(&mut self, well_known: &str) -> Result<Option<String>, SsBusError>;

    /// `GetConnectionUnixProcessID` (+ peer uid) for one bus name.
    fn peer_credentials(&mut self, name: &str) -> Result<PeerCredentials, SsBusError>;

    /// `OpenSession(algorithm, public_key)` bound to `dest`; returns the peer
    /// public key and the negotiated session object path.
    fn open_session(
        &mut self,
        dest: &str,
        algorithm: &str,
        public_key: Vec<u8>,
    ) -> Result<(Vec<u8>, String), SsBusError>;

    /// `ReadAlias(alias)` bound to `dest`: collection path or `None` for "/".
    fn read_alias(&mut self, dest: &str, alias: &str) -> Result<Option<String>, SsBusError>;

    /// `SearchItems(attributes)` bound to `dest`, split by lock state.
    fn search_items(
        &mut self,
        dest: &str,
        attributes: &[(String, String)],
    ) -> Result<SsSearchOutcome, SsBusError>;

    /// `GetSecret(session)` on one item bound to `dest`.
    fn get_secret(
        &mut self,
        dest: &str,
        session_path: &str,
        item: &str,
    ) -> Result<WireSecret, SsBusError>;

    /// `SetSecret` on one existing item bound to `dest`.
    fn set_item_secret(
        &mut self,
        dest: &str,
        item: &str,
        secret: WireSecret,
    ) -> Result<SsMutationOutcome, SsBusError>;

    /// `CreateItem(properties, secret, replace)` in one collection bound to
    /// `dest`; returns the created item path when no prompt was required.
    fn create_item(
        &mut self,
        dest: &str,
        collection: &str,
        label: &str,
        attributes: &[(String, String)],
        secret: WireSecret,
        replace: bool,
    ) -> Result<(Option<String>, SsMutationOutcome), SsBusError>;

    /// `Delete` one item bound to `dest`.
    fn delete_item(&mut self, dest: &str, item: &str) -> Result<SsMutationOutcome, SsBusError>;
}
