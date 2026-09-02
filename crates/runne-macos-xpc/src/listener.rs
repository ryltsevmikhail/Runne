use std::sync::Arc;

use zeroize::Zeroizing;

use crate::{
    CredentialServiceEndpointConfiguration, CredentialServiceEndpointRole,
    CredentialServiceXpcError,
};

#[cfg(target_os = "macos")]
mod native;

/// Domain handler invoked after native endpoint and peer admission.
pub trait CredentialServiceRequestHandler: Send + Sync {
    /// Consumes one bounded frame and returns one bounded reply frame.
    ///
    /// # Errors
    ///
    /// Returns only a closed transport/service disposition.
    fn handle(
        &self,
        role: CredentialServiceEndpointRole,
        request: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError>;
}

pub fn invoke_handler(
    handler: &dyn CredentialServiceRequestHandler,
    role: CredentialServiceEndpointRole,
    request: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handler.handle(role, request)
    }))
    .unwrap_or(Err(CredentialServiceXpcError::Unavailable))
}

/// Retained native listener; no Foundation object crosses this boundary.
pub struct CredentialServiceXpcListener {
    #[cfg(target_os = "macos")]
    native: native::NativeListener,
}

impl CredentialServiceXpcListener {
    /// Binds one exact role endpoint with its client signing requirement.
    ///
    /// # Errors
    ///
    /// Returns typed unsupported off macOS or a closed native failure.
    pub fn bind(
        configuration: &CredentialServiceEndpointConfiguration,
        handler: Arc<dyn CredentialServiceRequestHandler>,
    ) -> Result<Self, CredentialServiceXpcError> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                native: native::NativeListener::bind(configuration, handler),
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (configuration, handler);
            Err(CredentialServiceXpcError::Unsupported)
        }
    }

    /// Invalidates the native listener immediately.
    pub fn invalidate(&self) {
        #[cfg(target_os = "macos")]
        self.native.invalidate();
    }
}
