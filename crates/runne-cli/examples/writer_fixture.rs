//! TEST-ONLY first-party writer fixture entry (explicitly not production):
//! identical trust path to the internal broker entry, but the Linux
//! provider-credential store source is an in-memory FAKE installed through
//! the established `test-support` seam of runne-secure-store. Built only on
//! demand by the private-socket entry test; never staged or shipped.
//! Only authenticates and constructs the writer; does not claim or execute
//! a credential effect. Exit success is not full enrollment evidence.

#[cfg(target_os = "linux")]
use std::io::Read as _;

#[cfg(target_os = "linux")]
use runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession;
#[cfg(target_os = "linux")]
use runne_secure_store::NativeProviderCredentialWriters;
#[cfg(target_os = "linux")]
use runne_secure_store::{CountingFakeSource, install_test_source};

#[cfg(target_os = "linux")]
fn main() {
    // Fixture store state only — no real Secret Service or keyutils contact.
    let fake = CountingFakeSource::unlocked();
    let _fake_guard = install_test_source(Box::new(fake));
    let session =
        AuthenticatedProviderCredentialWriterSession::receive_linux_authenticated_writer()
            .expect("authenticated writer entry");
    let writers = NativeProviderCredentialWriters::from_authenticated_session(session)
        .expect("authenticated writers");
    let (mut control, _channel, ticket, _issuer, effect_route) = writers
        .into_authenticated_parts()
        .expect("authenticated parts");
    // The parent coalesces this marker after IssueTicket. Entry must preserve
    // both the next control bytes and the signed qualification mode.
    let mut marker = [0; 8];
    control.read_exact(&mut marker).expect("next control bytes");
    assert_eq!(
        &marker,
        if ticket.is_qualified() {
            b"fixture2"
        } else {
            b"fixture1"
        }
    );
    drop(control);
    drop(ticket);
    drop(effect_route);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this fixture is Linux-only");
    std::process::exit(1);
}
