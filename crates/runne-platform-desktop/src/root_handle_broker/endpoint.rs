use std::os::unix::net::UnixStream;
use std::time::Duration;

use runne_api::{RootHandleTransferAuthenticator, RootHandleTransferContext};

use super::{
    RootHandleBrokerError, RootHandleTransferBinding, VerifiedRootHandle,
    binding_for_protected_control, platform,
};

/// Typed owner for one protected native descriptor phase.
pub struct ProtectedRootHandleEndpoint {
    channel: Option<UnixStream>,
    authenticator: RootHandleTransferAuthenticator,
    binding: RootHandleTransferBinding,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    phase: EndpointPhase,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum EndpointPhase {
    Fresh,
    Sent,
    Received,
    Finished,
}

impl ProtectedRootHandleEndpoint {
    /// Adopts an owned inherited endpoint after the authenticated offer phase.
    ///
    /// # Errors
    ///
    /// Returns a closed failure if native timeout state or the signed binding is invalid.
    pub fn from_owned_protected_channel(
        channel: UnixStream,
        authenticator: RootHandleTransferAuthenticator,
        context: &RootHandleTransferContext,
        offer_digest: [u8; 32],
    ) -> Result<Self, RootHandleBrokerError> {
        let read_timeout = channel
            .read_timeout()
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        let write_timeout = channel
            .write_timeout()
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        Ok(Self {
            channel: Some(channel),
            authenticator,
            binding: binding_for_protected_control(context, offer_digest)?,
            read_timeout,
            write_timeout,
            phase: EndpointPhase::Fresh,
        })
    }
    /// Sends exactly one verified descriptor.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the endpoint is already consumed or native transfer fails.
    pub fn send(&mut self, root: &VerifiedRootHandle) -> Result<(), RootHandleBrokerError> {
        if self.phase != EndpointPhase::Fresh {
            return Err(RootHandleBrokerError::Rejected);
        }
        self.phase = EndpointPhase::Sent;
        platform::send_borrowed(
            self.channel
                .as_mut()
                .ok_or(RootHandleBrokerError::Rejected)?,
            root,
            &self.authenticator,
            &self.binding,
        )
    }
    /// Receives exactly one verified descriptor.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the endpoint is already consumed or native transfer fails.
    pub fn receive(&mut self) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
        if self.phase != EndpointPhase::Fresh {
            return Err(RootHandleBrokerError::Rejected);
        }
        self.phase = EndpointPhase::Received;
        platform::receive_borrowed(
            self.channel
                .as_mut()
                .ok_or(RootHandleBrokerError::Rejected)?,
            &self.authenticator,
            &self.binding,
        )
    }
    /// Restores inherited channel deadlines after a synchronized terminal phase.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the endpoint is consumed or timeout restoration fails.
    pub fn finish(mut self) -> Result<(), RootHandleBrokerError> {
        if !matches!(self.phase, EndpointPhase::Sent | EndpointPhase::Received) {
            return Err(RootHandleBrokerError::Rejected);
        }
        let channel = self.channel.take().ok_or(RootHandleBrokerError::Rejected)?;
        channel
            .set_read_timeout(self.read_timeout)
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        channel
            .set_write_timeout(self.write_timeout)
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        self.phase = EndpointPhase::Finished;
        Ok(())
    }
}

impl Drop for ProtectedRootHandleEndpoint {
    fn drop(&mut self) {
        if self.phase == EndpointPhase::Fresh {
            if let Some(channel) = self.channel.take() {
                let _ = channel.set_read_timeout(self.read_timeout);
                let _ = channel.set_write_timeout(self.write_timeout);
            }
        } else if self.phase != EndpointPhase::Finished
            && let Some(channel) = self.channel.take()
        {
            use std::net::Shutdown;
            let _ = channel.shutdown(Shutdown::Both);
        }
    }
}
