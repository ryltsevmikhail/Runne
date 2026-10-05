use crate::ProviderToolDeclarationV1;

/// Read-only provider profile contract for explicit bounded tool calls.
///
/// Implementations are separate from text-only profile objects. A caller must
/// opt into this trait before tool declarations or tool results are accepted.
pub trait ToolProviderProfile: TextProviderProfile {
    /// Exact immutable declarations admitted by this profile.
    fn tool_declarations(&self) -> &[ProviderToolDeclarationV1];
}
