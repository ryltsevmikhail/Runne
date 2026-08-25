use std::fs::File;
use std::process::Child;

use runne_api::RootHandleTransferContext;
use runne_windows_native_handle::{ProtectedHandleReceiver, ProtectedHandleSender};

use super::{RootHandleBrokerError, VerifiedRootHandle};

enum EndpointRole {
    Sender(ProtectedHandleSender),
    Receiver(ProtectedHandleReceiver),
}

/// One-shot Windows root-handle endpoint bound to the signed transfer ID.
pub struct ProtectedRootHandleEndpoint {
    channel: Option<File>,
    role: EndpointRole,
    offer_id: [u8; 16],
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
    /// Creates the daemon-side receiver on an inherited protected channel.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the launch generation or channel is invalid.
    pub fn from_owned_protected_channel(
        channel: File,
        context: &RootHandleTransferContext,
        offer_id: [u8; 32],
    ) -> Result<Self, RootHandleBrokerError> {
        let role = ProtectedHandleReceiver::new(context.launch_generation())
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        let mut signed_id = [0; 16];
        signed_id.copy_from_slice(&context.transfer_id()[..]);
        if offer_id == [0; 32] {
            return Err(RootHandleBrokerError::Rejected);
        }
        Ok(Self {
            channel: Some(channel),
            role: EndpointRole::Receiver(role),
            offer_id: signed_id,
            phase: EndpointPhase::Fresh,
        })
    }

    /// Creates the launcher-side sender bound to the exact child process.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the child identity cannot be bound.
    pub fn from_parent_protected_channel(
        channel: File,
        child: &Child,
        context: &RootHandleTransferContext,
    ) -> Result<Self, RootHandleBrokerError> {
        let role = ProtectedHandleSender::from_child(child, context.launch_generation())
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        let mut offer_id = [0; 16];
        offer_id.copy_from_slice(context.transfer_id());
        Ok(Self {
            channel: Some(channel),
            role: EndpointRole::Sender(role),
            offer_id,
            phase: EndpointPhase::Fresh,
        })
    }

    /// Sends exactly one verified root into the protected child.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a consumed endpoint or native transfer failure.
    pub fn send(&mut self, root: &VerifiedRootHandle) -> Result<(), RootHandleBrokerError> {
        if self.phase != EndpointPhase::Fresh {
            return Err(RootHandleBrokerError::Rejected);
        }
        let EndpointRole::Sender(sender) = &mut self.role else {
            return Err(RootHandleBrokerError::Rejected);
        };
        sender
            .send(
                self.channel
                    .as_mut()
                    .ok_or(RootHandleBrokerError::Rejected)?,
                root.native_handle(),
                self.offer_id,
            )
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        self.phase = EndpointPhase::Sent;
        Ok(())
    }

    /// Receives exactly one verified root from the protected desktop.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or uncommitted native transfer.
    pub fn receive(&mut self) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
        if self.phase != EndpointPhase::Fresh {
            return Err(RootHandleBrokerError::Rejected);
        }
        let EndpointRole::Receiver(receiver) = &mut self.role else {
            return Err(RootHandleBrokerError::Rejected);
        };
        let directory = receiver
            .receive(
                self.channel
                    .as_mut()
                    .ok_or(RootHandleBrokerError::Rejected)?,
                self.offer_id,
            )
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        self.phase = EndpointPhase::Received;
        Ok(VerifiedRootHandle::from_native_handle(directory))
    }

    /// Finishes the one-shot endpoint after the outer signed result is sent.
    ///
    /// # Errors
    ///
    /// Returns a closed error when no native transfer was committed.
    pub fn finish(mut self) -> Result<(), RootHandleBrokerError> {
        if !matches!(self.phase, EndpointPhase::Sent | EndpointPhase::Received) {
            return Err(RootHandleBrokerError::Rejected);
        }
        let _ = self.channel.take().ok_or(RootHandleBrokerError::Rejected)?;
        self.phase = EndpointPhase::Finished;
        Ok(())
    }
}

impl Drop for ProtectedRootHandleEndpoint {
    fn drop(&mut self) {
        self.channel.take();
    }
}
