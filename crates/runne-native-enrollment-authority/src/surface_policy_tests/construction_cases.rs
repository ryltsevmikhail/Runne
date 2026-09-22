use std::fs;

use super::construction_violations;

const LINUX_LITERAL_CONSTRUCTOR: &str = r"
pub struct AuthenticatedProviderCredentialWriterSession { verified: VerifiedEnrollmentSession }
pub(crate) enum VerifiedEnrollmentSession {
    Linux(Box<(std::os::unix::net::UnixStream, [u8; 32], [u8; 32])>),
}
impl AuthenticatedProviderCredentialWriterSession {
    pub(crate) fn from_linux_verified_parts(control: std::os::unix::net::UnixStream, candidate: [u8; 32], pin: [u8; 32]) -> Self {
        Self { verified: VerifiedEnrollmentSession::Linux(Box::new((control, candidate, pin))) }
    }
}
";

const RAW_DIGEST_CONSTRUCTOR: &str = r"
pub struct AuthenticatedProviderCredentialWriterSession { verified: VerifiedEnrollmentSession }
pub(crate) enum VerifiedEnrollmentSession { Linux(Box<([u8; 32], [u8; 32])>) }
impl AuthenticatedProviderCredentialWriterSession {
    #[doc(hidden)]
    pub(crate) fn from_authority_measured_facts(candidate: [u8; 32], tuple: [u8; 32]) -> Self {
        Self { verified: VerifiedEnrollmentSession::Linux(Box::new((candidate, tuple))) }
    }
}
";

const ALIAS_CONSTRUCTOR: &str = r"
use crate::AuthenticatedProviderCredentialWriterSession as S;
use crate::session::VerifiedEnrollmentSession as V;
pub(crate) fn mint_session(candidate: [u8; 32], tuple: [u8; 32]) -> S {
    S { verified: V::Linux(Box::new((candidate, tuple))) }
}
";

fn assert_flagged(source: &str) {
    let mut violations = super::super::authority_surface_violations(source);
    violations.extend(construction_violations(source, "mutation"));
    assert!(
        !violations.is_empty(),
        "mutation escaped the authority audits"
    );
}

#[test]
fn uncontrolled_linux_literal_constructor_is_flagged() {
    assert_flagged(LINUX_LITERAL_CONSTRUCTOR);
}

#[test]
fn raw_digest_session_constructor_is_flagged() {
    assert_flagged(RAW_DIGEST_CONSTRUCTOR);
}

#[test]
fn renamed_alias_constructor_is_flagged() {
    assert_flagged(ALIAS_CONSTRUCTOR);
}

#[test]
fn session_literal_in_session_module_outside_mint_is_flagged() {
    let source = r"
pub struct AuthenticatedProviderCredentialWriterSession { verified: VerifiedEnrollmentSession }
pub(crate) enum VerifiedEnrollmentSession { Verified }
impl AuthenticatedProviderCredentialWriterSession {
    pub(crate) fn from_linux_verified_parts(parts: VerifiedEnrollmentSession) -> Self {
        Self { verified: parts }
    }
}
";
    assert!(
        !construction_violations(source, "crates/x/src/session.rs").is_empty(),
        "a session constructor outside the reviewed mint fn must not be blessable in-session"
    );
}

#[test]
fn production_session_construction_happens_only_at_reviewed_sites() {
    let mut violations = Vec::new();
    for path in super::production_sources() {
        let source = fs::read_to_string(&path).unwrap();
        violations.extend(construction_violations(
            &source,
            &path.display().to_string(),
        ));
    }
    assert!(
        violations.is_empty(),
        "unreviewed authority construction sites: {violations:#?}"
    );
}
