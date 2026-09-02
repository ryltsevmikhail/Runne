use std::num::NonZeroU32;
use std::os::fd::AsFd;

use nix::sys::stat::fstat;

use crate::{MacOsLocalPeerProcessIdentity, MacOsLocalPeerProcessIdentityError, ffi};

/// Validates an inherited stream against the exact current package parent.
///
/// # Errors
///
/// Fails closed unless a Unix socket's kernel-audited peer is the exact
/// expected parent and all three processes retain one session.
pub fn validate_current_parent_channel<S: AsFd>(
    stream: &S,
    expected_parent: NonZeroU32,
) -> Result<(), MacOsLocalPeerProcessIdentityError> {
    let metadata = fstat(stream).map_err(|_| MacOsLocalPeerProcessIdentityError::Rejected)?;
    let peer = MacOsLocalPeerProcessIdentity::capture(stream)?;
    peer.revalidate_same_peer(stream)?;
    let peer_group =
        ffi::peer_group_id(stream).map_err(|_| MacOsLocalPeerProcessIdentityError::Rejected)?;
    let current_parent = current_parent_pid()?;
    channel_is_bound(
        metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK,
        peer_group == ffi::effective_group_id(),
        peer.pid(),
        expected_parent,
        current_parent,
        same_session(peer.pid(), current_parent),
    )
    .then_some(())
    .ok_or(MacOsLocalPeerProcessIdentityError::Rejected)
}

fn current_parent_pid() -> Result<NonZeroU32, MacOsLocalPeerProcessIdentityError> {
    ffi::current_parent_pid().map_err(|_| MacOsLocalPeerProcessIdentityError::Rejected)
}

fn same_session(peer: NonZeroU32, parent: NonZeroU32) -> bool {
    matches!(
        (
            ffi::session_id(None),
            ffi::session_id(Some(parent)),
            ffi::session_id(Some(peer)),
        ),
        (Ok(current), Ok(parent), Ok(peer)) if current == parent && parent == peer
    )
}

fn channel_is_bound(
    socket: bool,
    group_matches: bool,
    peer_pid: NonZeroU32,
    expected_parent: NonZeroU32,
    current_parent: NonZeroU32,
    session_matches: bool,
) -> bool {
    socket
        && group_matches
        && peer_pid == expected_parent
        && current_parent == expected_parent
        && session_matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_requires_exact_peer_and_retained_parent() {
        let parent = NonZeroU32::new(std::process::id()).unwrap();
        let unrelated = NonZeroU32::new(parent.get().wrapping_add(1)).unwrap();
        assert!(channel_is_bound(true, true, parent, parent, parent, true));
        assert!(!channel_is_bound(false, true, parent, parent, parent, true));
        assert!(!channel_is_bound(true, false, parent, parent, parent, true));
        assert!(!channel_is_bound(
            true, true, unrelated, parent, parent, true
        ));
        assert!(!channel_is_bound(
            true, true, parent, unrelated, unrelated, true
        ));
        assert!(!channel_is_bound(true, true, parent, parent, parent, false));
    }
}
