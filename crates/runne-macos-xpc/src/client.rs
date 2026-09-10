use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServiceDesktopPort, CredentialServiceDesktopReply,
    CredentialServiceDesktopRequest, CredentialServicePortError, CredentialServicePortFuture,
    CredentialServiceQualificationPort, CredentialServiceQualificationReply,
    CredentialServiceQualificationRequest, CredentialServiceRuntimePort,
    CredentialServiceRuntimeReply, CredentialServiceRuntimeRequest, CredentialServiceWriterPort,
    CredentialServiceWriterReply, CredentialServiceWriterRequest,
};
use zeroize::Zeroizing;

use crate::{
    CredentialServiceEndpointConfiguration, CredentialServiceEndpointRole,
    CredentialServiceXpcError,
};

#[cfg(test)]
#[derive(Clone, Copy)]
pub enum CallEvent {
    Reply,
    Timeout,
    Cancelled,
    Interrupted,
    Invalidated,
}

#[cfg(test)]
pub struct PendingCall {
    started_at: u64,
    expires_at: u64,
    terminal: bool,
}

#[cfg(test)]
impl PendingCall {
    pub(crate) fn new(started_at: u64, expires_at: u64) -> Result<Self, CredentialServiceXpcError> {
        if expires_at <= started_at {
            return Err(CredentialServiceXpcError::Rejected);
        }
        Ok(Self {
            started_at,
            expires_at,
            terminal: false,
        })
    }

    pub(crate) fn apply(
        &mut self,
        event: CallEvent,
        now: u64,
    ) -> Result<(), CredentialServiceXpcError> {
        if self.terminal {
            return Err(CredentialServiceXpcError::InvalidReply);
        }
        self.terminal = true;
        if now < self.started_at {
            return Err(CredentialServiceXpcError::Rejected);
        }
        if now >= self.expires_at || matches!(event, CallEvent::Timeout) {
            return Err(CredentialServiceXpcError::OutcomeUnknown);
        }
        match event {
            CallEvent::Reply => Ok(()),
            CallEvent::Cancelled | CallEvent::Interrupted | CallEvent::Invalidated => {
                Err(CredentialServiceXpcError::OutcomeUnknown)
            }
            CallEvent::Timeout => unreachable!("timeout handled above"),
        }
    }
}

struct ClientCore {
    #[cfg(target_os = "macos")]
    native: native::NativeClient,
}

impl ClientCore {
    #[cfg(target_os = "macos")]
    fn connect(
        configuration: &CredentialServiceEndpointConfiguration,
    ) -> Result<Self, CredentialServiceXpcError> {
        Ok(Self {
            native: native::NativeClient::connect(configuration)?,
        })
    }

    #[cfg(not(target_os = "macos"))]
    const fn connect(
        _: &CredentialServiceEndpointConfiguration,
    ) -> Result<Self, CredentialServiceXpcError> {
        Err(CredentialServiceXpcError::Unsupported)
    }

    fn exchange(
        &self,
        bytes: Zeroizing<Vec<u8>>,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, Zeroizing<Vec<u8>>> {
        #[cfg(target_os = "macos")]
        return Box::pin(async move {
            self.native
                .exchange(bytes, context)
                .await
                .map(crate::frame::NativeReplyFrame::into_bytes)
                .map_err(Into::into)
        });
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (self, bytes, context);
            Box::pin(async { Err(CredentialServiceXpcError::Unsupported.into()) })
        }
    }
}

macro_rules! role_client {
    ($name:ident, $role:ident) => {
        pub struct $name(ClientCore);

        impl $name {
            /// Connects only to this client's exact role endpoint.
            ///
            /// # Errors
            ///
            /// Rejects role skew and returns typed unsupported outside macOS.
            pub fn connect(
                configuration: CredentialServiceEndpointConfiguration,
            ) -> Result<Self, CredentialServiceXpcError> {
                if configuration.role() != CredentialServiceEndpointRole::$role {
                    return Err(CredentialServiceXpcError::Rejected);
                }
                ClientCore::connect(&configuration).map(Self)
            }
        }
    };
}

role_client!(CredentialServiceDesktopXpcClient, Desktop);
role_client!(CredentialServiceRuntimeXpcClient, Runtime);
role_client!(CredentialServiceWriterXpcClient, Writer);

macro_rules! exchange_method {
    ($self:ident, $request:ident, $context:ident, $reply:ty) => {{
        Box::pin(async move {
            let bytes = $self
                .0
                .exchange($request.into_zeroizing(), $context)
                .await?;
            <$reply>::from_zeroizing(bytes)
        })
    }};
}

impl CredentialServiceDesktopPort for CredentialServiceDesktopXpcClient {
    fn challenge(
        &self,
        request: CredentialServiceDesktopRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply> {
        exchange_method!(self, request, context, CredentialServiceDesktopReply)
    }

    fn register(
        &self,
        request: CredentialServiceDesktopRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply> {
        exchange_method!(self, request, context, CredentialServiceDesktopReply)
    }
}

impl CredentialServiceRuntimePort for CredentialServiceRuntimeXpcClient {
    fn arm_mutation(
        &self,
        request: CredentialServiceRuntimeRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        exchange_method!(self, request, context, CredentialServiceRuntimeReply)
    }

    fn read_metadata(
        &self,
        request: CredentialServiceRuntimeRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        exchange_method!(self, request, context, CredentialServiceRuntimeReply)
    }

    fn read_material(
        &self,
        request: CredentialServiceRuntimeRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        exchange_method!(self, request, context, CredentialServiceRuntimeReply)
    }
}

impl CredentialServiceQualificationPort for CredentialServiceRuntimeXpcClient {
    fn qualify(
        &self,
        request: CredentialServiceQualificationRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceQualificationReply> {
        Box::pin(async move {
            let _ = (request, context);
            Err(CredentialServicePortError::Unsupported)
        })
    }
}

impl CredentialServiceWriterPort for CredentialServiceWriterXpcClient {
    fn consume_mutation(
        &self,
        request: CredentialServiceWriterRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceWriterReply> {
        exchange_method!(self, request, context, CredentialServiceWriterReply)
    }
}

#[cfg(target_os = "macos")]
mod native;
