//! Test-support constructors for the one-shot authenticated transfer pair.
//!
//! Split out of the broker root module by responsibility: production transfer
//! surface stays in `root_handle_broker.rs`, synthetic/test-only constructors
//! live here behind `feature = "test-support"`.

use super::platform;
use super::{
    RootHandleBrokerError, RootHandleTransferBinding, RootHandleTransferReceiver,
    RootHandleTransferSender,
};
use runne_api::RootHandleTransferAuthenticator;

/// Creates a test-only one-shot local sender/receiver pair.
///
/// # Errors
///
/// Returns a closed error when the native test transport is unavailable.
pub fn test_transfer_pair(
    sender_authenticator: RootHandleTransferAuthenticator,
    receiver_authenticator: RootHandleTransferAuthenticator,
    binding: RootHandleTransferBinding,
) -> Result<(RootHandleTransferSender, RootHandleTransferReceiver), RootHandleBrokerError> {
    let (sender, receiver) = platform::test_pair()?;
    Ok((
        RootHandleTransferSender {
            channel: Some(sender),
            authenticator: sender_authenticator,
            binding: binding.clone(),
        },
        RootHandleTransferReceiver {
            channel: Some(receiver),
            authenticator: receiver_authenticator,
            binding,
        },
    ))
}

#[cfg(unix)]
#[doc(hidden)]
#[must_use]
pub const fn test_transfer_sender(
    channel: std::os::unix::net::UnixStream,
    authenticator: RootHandleTransferAuthenticator,
    binding: RootHandleTransferBinding,
) -> RootHandleTransferSender {
    RootHandleTransferSender {
        channel: Some(channel),
        authenticator,
        binding,
    }
}

#[cfg(unix)]
#[doc(hidden)]
#[must_use]
pub const fn test_transfer_receiver(
    channel: std::os::unix::net::UnixStream,
    authenticator: RootHandleTransferAuthenticator,
    binding: RootHandleTransferBinding,
) -> RootHandleTransferReceiver {
    RootHandleTransferReceiver {
        channel: Some(channel),
        authenticator,
        binding,
    }
}

#[cfg(unix)]
#[doc(hidden)]
#[must_use]
pub fn launcher_spawn_attempt_count() -> u32 {
    platform::launcher_spawn_attempt_count()
}
