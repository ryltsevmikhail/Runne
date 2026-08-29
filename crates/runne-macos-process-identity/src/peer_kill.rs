#![allow(unsafe_code)]

use std::num::NonZeroU32;
use std::os::fd::AsFd;

use nix::sys::socket::{getsockopt, sockopt};

use crate::MacOsProcessStartIdentity;

type ProcSignalWithAuditToken =
    unsafe extern "C" fn(*mut nix::sys::socket::audit_token_t, libc::c_int) -> libc::c_int;

#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_pid(token: nix::sys::socket::audit_token_t) -> libc::pid_t;
    fn audit_token_to_pidversion(token: nix::sys::socket::audit_token_t) -> libc::c_int;
    fn audit_token_to_euid(token: nix::sys::socket::audit_token_t) -> libc::uid_t;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPeerKillError {
    Rejected,
    Unavailable,
}

pub struct MacOsPeerKillCapability {
    token: nix::sys::socket::audit_token_t,
    pid: NonZeroU32,
    start: [u8; 32],
    resolver: ResolvedSignal,
}

struct ResolvedSignal {
    library: *mut libc::c_void,
    function: ProcSignalWithAuditToken,
}

#[derive(Clone, Copy)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "native facade selects the private resolver"
)]
pub(super) enum Resolver {
    Runtime,
    #[cfg(feature = "test-support")]
    Test(bool),
}

impl MacOsPeerKillCapability {
    /// Terminates only the still-identical captured peer.
    ///
    /// # Errors
    ///
    /// Fails closed after peer replacement or kernel signal rejection.
    pub fn terminate_exact_peer(mut self) -> Result<(), MacOsPeerKillError> {
        (MacOsProcessStartIdentity::observe(self.pid)
            .map_err(|_| MacOsPeerKillError::Rejected)?
            .digest()
            == self.start)
            .then_some(())
            .ok_or(MacOsPeerKillError::Rejected)?;
        let status = unsafe { (self.resolver.function)(&raw mut self.token, libc::SIGKILL) };
        (status == 0)
            .then_some(())
            .ok_or(MacOsPeerKillError::Rejected)
    }
}

impl Drop for ResolvedSignal {
    fn drop(&mut self) {
        let _ = unsafe { libc::dlclose(self.library) };
    }
}

impl std::fmt::Debug for MacOsPeerKillCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacOsPeerKillCapability(<kernel-local-peer>)")
    }
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "native facade owns the only full-bound capture entrypoint"
)]
pub(super) fn capture<S: AsFd>(
    stream: &S,
    expected_start: [u8; 32],
    resolver: Resolver,
) -> Result<MacOsPeerKillCapability, MacOsPeerKillError> {
    let token =
        getsockopt(stream, sockopt::LocalPeerToken).map_err(|_| MacOsPeerKillError::Rejected)?;
    let pid =
        getsockopt(stream, sockopt::LocalPeerPid).map_err(|_| MacOsPeerKillError::Rejected)?;
    let pid = NonZeroU32::new(u32::try_from(pid).map_err(|_| MacOsPeerKillError::Rejected)?)
        .ok_or(MacOsPeerKillError::Rejected)?;
    let credentials =
        getsockopt(stream, sockopt::LocalPeerCred).map_err(|_| MacOsPeerKillError::Rejected)?;
    token_matches_peer(&token, pid, credentials.uid(), effective_uid())
        .then_some(())
        .ok_or(MacOsPeerKillError::Rejected)?;
    let start = MacOsProcessStartIdentity::observe(pid)
        .map_err(|_| MacOsPeerKillError::Rejected)?
        .digest();
    (expected_start != [0; 32] && start == expected_start)
        .then_some(())
        .ok_or(MacOsPeerKillError::Rejected)?;
    Ok(MacOsPeerKillCapability {
        token,
        pid,
        start,
        resolver: resolve(resolver)?,
    })
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling local_peer shares the crate-private kernel observation"
)]
pub(super) fn token_matches_peer(
    token: &nix::sys::socket::audit_token_t,
    pid: NonZeroU32,
    peer_euid: u32,
    expected_euid: u32,
) -> bool {
    let token_pid = unsafe { audit_token_to_pid(*token) };
    let pidversion = unsafe { audit_token_to_pidversion(*token) };
    let token_euid = unsafe { audit_token_to_euid(*token) };
    u32::try_from(token_pid).is_ok_and(|token_pid| token_pid == pid.get())
        && token_euid == peer_euid
        && token_euid == expected_euid
        && pidversion > 0
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling local_peer compares the crate-private audit token"
)]
pub(super) fn same_audit_token(
    first: &nix::sys::socket::audit_token_t,
    second: &nix::sys::socket::audit_token_t,
) -> bool {
    first.val == second.val
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling local_peer needs the same current-user observation"
)]
pub(super) fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn resolve(resolver: Resolver) -> Result<ResolvedSignal, MacOsPeerKillError> {
    #[cfg(not(feature = "test-support"))]
    let _ = resolver;
    #[cfg(feature = "test-support")]
    if matches!(resolver, Resolver::Test(false)) {
        return Err(MacOsPeerKillError::Unavailable);
    }
    let library = unsafe {
        libc::dlopen(
            c"/usr/lib/libSystem.B.dylib".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    if library.is_null() {
        return Err(MacOsPeerKillError::Unavailable);
    }
    let symbol = unsafe { libc::dlsym(library, c"proc_signal_with_audittoken".as_ptr()) };
    if symbol.is_null() {
        let _ = unsafe { libc::dlclose(library) };
        return Err(MacOsPeerKillError::Unavailable);
    }
    let function =
        unsafe { std::mem::transmute::<*mut libc::c_void, ProcSignalWithAuditToken>(symbol) };
    Ok(ResolvedSignal { library, function })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_token_pid_and_pidversion_must_be_complete() {
        let (local, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let token = getsockopt(&local, sockopt::LocalPeerToken).unwrap();
        let pid = getsockopt(&local, sockopt::LocalPeerPid).unwrap();
        let pid = NonZeroU32::new(u32::try_from(pid).unwrap()).unwrap();
        let euid = unsafe { libc::geteuid() };
        assert!(token_matches_peer(&token, pid, euid, euid));
        assert!(!token_matches_peer(
            &token,
            pid,
            euid.checked_add(1).unwrap_or_default(),
            euid
        ));
        let different = NonZeroU32::new(pid.get().checked_add(1).unwrap()).unwrap();
        assert!(!token_matches_peer(&token, different, euid, euid));
        assert!(!token_matches_peer(
            &nix::sys::socket::audit_token_t::default(),
            pid,
            euid,
            euid
        ));
    }
}
