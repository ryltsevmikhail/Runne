/// Native-host transport authority used to construct an authenticated client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeTransportKind {
    /// Explicit external daemon using the owner-only credential profile.
    ExternalLocal,
    /// Supervised bundled daemon admitted over the protected launch channel.
    ProtectedBundled,
}
