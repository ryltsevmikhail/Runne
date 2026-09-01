#![cfg(test)]

use super::authority_surface_violations;

const EXACT_HANDOFF: &str = r"
pub struct UntrustedProviderCredentialWriterEndpointHandoffV1 {
    inner: runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1,
}
impl UntrustedProviderCredentialWriterEndpointHandoffV1 {
    pub fn receive_from_stdin() -> std::io::Result<Self> { todo!() }
}
";

const EXACT_PINNED: &str = r"
pub struct PendingPinnedProviderCredentialWriterSessionV1 {
    inner: runne_macos_process_identity::MacOsPendingProvisionalWriterSessionV1,
}
impl UntrustedProviderCredentialWriterEndpointHandoffV1 {
    pub fn observe_current_pinned_writer_session(self) -> Result<PendingPinnedProviderCredentialWriterSessionV1, runne_macos_process_identity::MacOsPackagedWriterObservationError> { todo!() }
}
impl PendingPinnedProviderCredentialWriterSessionV1 {
    pub fn authenticate_current_writer(self) -> Result<AuthenticatedProviderCredentialWriterSession, runne_macos_process_identity::MacOsPackagedWriterObservationError> { todo!() }
}
";

#[test]
fn authority_surface_accepts_only_the_exact_handoff_shape() {
    assert!(
        authority_surface_violations(EXACT_HANDOFF).is_empty(),
        "the exact wrapper shape must remain representable"
    );
}

#[test]
fn authority_surface_accepts_only_the_exact_pinned_shape() {
    assert!(
        authority_surface_violations(EXACT_PINNED).is_empty(),
        "the exact pinned shape must remain representable"
    );
}

#[test]
fn authority_surface_rejects_pinned_shape_mutations() {
    let cases = [
        EXACT_PINNED.replace("MacOsPendingProvisionalWriterSessionV1", "OwnedFd"),
        EXACT_PINNED.replace("    inner:", "    pub inner:"),
        EXACT_PINNED.replace(
            "observe_current_pinned_writer_session(self)",
            "observe_current_pinned_writer_session(&self)",
        ),
        EXACT_PINNED.replace(
            "Result<PendingPinnedProviderCredentialWriterSessionV1, runne_macos_process_identity::MacOsPackagedWriterObservationError>",
            "Result<AuthenticatedProviderCredentialWriterSession, ()>",
        ),
        EXACT_PINNED.replace(
            "    pub fn observe_current_pinned_writer_session",
            "    #[cfg(any())]\n    pub fn observe_current_pinned_writer_session",
        ),
        EXACT_PINNED.replace(
            "authenticate_current_writer(self)",
            "authenticate_current_writer(&self)",
        ),
        EXACT_PINNED.replace(
            "Result<AuthenticatedProviderCredentialWriterSession, runne_macos_process_identity::MacOsPackagedWriterObservationError>",
            "AuthenticatedProviderCredentialWriterSession",
        ),
    ];
    let accepted: Vec<_> = cases
        .iter()
        .enumerate()
        .filter_map(|(index, source)| {
            authority_surface_violations(source)
                .is_empty()
                .then_some(index)
        })
        .collect();
    assert!(accepted.is_empty(), "policy accepted {accepted:?}");
}

#[test]
fn authority_surface_rejects_handoff_shape_mutations() {
    let cases = [
        (
            "wrong field type",
            EXACT_HANDOFF.replace("MacOsUntrustedWriterEndpointHandoffV1", "OwnedFd"),
        ),
        (
            "second field",
            EXACT_HANDOFF.replace("inner:", "other: (), inner:"),
        ),
        (
            "public field",
            EXACT_HANDOFF.replace("    inner:", "    pub inner:"),
        ),
        (
            "cfg-hidden field",
            EXACT_HANDOFF.replace("    inner:", "    #[cfg(any())]\n    inner:"),
        ),
        (
            "cfg-hidden struct",
            EXACT_HANDOFF.replacen("pub struct", "#[cfg(any())] pub struct", 1),
        ),
        (
            "cfg-hidden impl",
            EXACT_HANDOFF.replacen("impl ", "#[cfg(any())] impl ", 1),
        ),
        (
            "receiver argument",
            EXACT_HANDOFF.replace("receive_from_stdin()", "receive_from_stdin(fd: i32)"),
        ),
        (
            "receiver self",
            EXACT_HANDOFF.replace("receive_from_stdin()", "receive_from_stdin(self)"),
        ),
        (
            "generic receiver",
            EXACT_HANDOFF.replace("receive_from_stdin()", "receive_from_stdin<T>()"),
        ),
        (
            "short result path",
            EXACT_HANDOFF.replace("std::io::Result<Self>", "std::io::Result<()>"),
        ),
        (
            "getter",
            format!(
                "{EXACT_HANDOFF} impl UntrustedProviderCredentialWriterEndpointHandoffV1 {{ pub fn as_raw_fd(&self) -> i32 {{ 0 }} }}"
            ),
        ),
        (
            "trait impl",
            format!(
                "{EXACT_HANDOFF} impl AsRef<()> for UntrustedProviderCredentialWriterEndpointHandoffV1 {{ fn as_ref(&self) -> &() {{ &() }} }}"
            ),
        ),
        (
            "conversion to authenticated session",
            format!(
                "{EXACT_HANDOFF} impl From<UntrustedProviderCredentialWriterEndpointHandoffV1> for AuthenticatedProviderCredentialWriterSession {{ fn from(_: UntrustedProviderCredentialWriterEndpointHandoffV1) -> Self {{ todo!() }} }}"
            ),
        ),
        (
            "alternate re-export",
            "pub use elsewhere::UntrustedProviderCredentialWriterEndpointHandoffV1;".into(),
        ),
        (
            "signature cfg substitution",
            EXACT_HANDOFF.replace(
                "    pub fn receive_from_stdin",
                "    #[cfg(any())]\n    pub fn receive_from_stdin",
            ),
        ),
    ];

    let accepted: Vec<_> = cases
        .into_iter()
        .filter_map(|(case, source)| {
            authority_surface_violations(&source)
                .is_empty()
                .then_some(case)
        })
        .collect();
    assert!(accepted.is_empty(), "policy accepted {accepted:?}");
}

#[test]
fn authority_surface_rejects_alternate_public_mint_shapes() {
    let cases = [
        (
            "public field",
            "pub struct AuthenticatedProviderCredentialWriterSession { pub verified: () }",
        ),
        (
            "alternate constructor",
            "impl AuthenticatedProviderCredentialWriterSession { pub fn mint_unverified(path: &str) -> Self { todo!() } }",
        ),
        (
            "bare-parts factory",
            "pub fn from_parts() -> AuthenticatedWriterEffectAdmission { todo!() }",
        ),
        (
            "aliased constructor",
            "type WriterSession = AuthenticatedProviderCredentialWriterSession; pub fn from_digest() -> WriterSession { todo!() }",
        ),
        (
            "wrapper constructor",
            "struct Wrapper; impl Wrapper { pub fn into_session(self) -> AuthenticatedProviderCredentialWriterSession { todo!() } }",
        ),
        (
            "array constructor",
            "pub fn mint_many() -> [AuthenticatedProviderCredentialWriterSession; 1] { todo!() }",
        ),
        (
            "function-pointer factory",
            "pub type WriterFactory = fn() -> AuthenticatedProviderCredentialWriterSession;",
        ),
        (
            "public enum wrapper",
            "pub enum WriterSession { Admitted(AuthenticatedProviderCredentialWriterSession) }",
        ),
        (
            "generic-default wrapper",
            "pub struct Envelope<T = AuthenticatedProviderCredentialWriterSession>(pub T);",
        ),
        (
            "generic where-clause factory",
            "pub fn mint<T>() -> T where AuthenticatedProviderCredentialWriterSession: Into<T> { todo!() }",
        ),
        (
            "type-erased factory",
            "pub fn mint_erased() -> Box<dyn std::any::Any> { todo!() }",
        ),
        (
            "derived default constructor",
            "#[derive(Default)] enum Verified { #[default] Yes } #[derive(Default)] pub struct AuthenticatedProviderCredentialWriterSession { verified: Verified }",
        ),
        (
            "cfg-conditional raw derive constructor",
            "#[cfg_attr(any(), r#derive(Default))] pub struct AuthenticatedProviderCredentialWriterSession { verified: () }",
        ),
        (
            "production-only module substitution",
            "#[cfg_attr(not(test), path = \"backdoor.inc\")] mod session;",
        ),
        (
            "aliased authority substitution",
            "pub use runne_provider::CredentialWriterEffectAuthority as AuthenticatedWriterEffectAdmission;",
        ),
        (
            "instantiated wrapper impl",
            "pub struct Envelope<T>(pub T); impl Envelope<AuthenticatedProviderCredentialWriterSession> { pub fn mint_unverified() -> Self { todo!() } }",
        ),
        (
            "opaque impl source macro",
            "impl AuthenticatedProviderCredentialWriterSession { include!(\"mint.inc\"); }",
        ),
        (
            "implementable proof",
            "pub trait CallerProof { fn admit(self) -> AuthenticatedProviderCredentialWriterSession; }",
        ),
        (
            "borrowed split",
            "impl AuthenticatedProviderCredentialWriterSession { pub fn split(&self) {} }",
        ),
        (
            "cfg-hidden exact split",
            "#[cfg(any())] impl AuthenticatedProviderCredentialWriterSession { pub fn split(self) -> (AuthenticatedWriterClaimContext, AuthenticatedWriterEffectAdmission) { todo!() } }",
        ),
    ];

    let accepted: Vec<_> = cases
        .into_iter()
        .filter_map(|(case, source)| {
            authority_surface_violations(source)
                .is_empty()
                .then_some(case)
        })
        .collect();
    assert!(accepted.is_empty(), "policy accepted {accepted:?}");
}
