#![cfg(test)]

use super::authority_surface_violations;

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
