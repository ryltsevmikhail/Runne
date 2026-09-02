use zeroize::Zeroizing;

/// Move-only zeroizing canonical credential-service request frame.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_provider::CredentialServiceRequestFrame>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_provider::CredentialServiceRequestFrame>();
/// ```
pub struct CredentialServiceRequestFrame(pub(super) Zeroizing<Vec<u8>>);

/// Move-only zeroizing context-bound credential-service reply frame.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_provider::CredentialServiceReplyFrame>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_provider::CredentialServiceReplyFrame>();
/// ```
pub struct CredentialServiceReplyFrame(pub(super) Zeroizing<Vec<u8>>);

/// Move-only zeroizing runtime-to-writer broker handoff frame.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_provider::CredentialWriterBrokerHandoffFrame>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_provider::CredentialWriterBrokerHandoffFrame>();
/// ```
pub struct CredentialWriterBrokerHandoffFrame(pub(super) Zeroizing<Vec<u8>>);

macro_rules! frame_api {
    ($name:ident) => {
        impl $name {
            /// Consumes bytes only at the authenticated service transport boundary.
            pub fn send<E>(self, send: impl FnOnce(&[u8]) -> Result<(), E>) -> Result<(), E> {
                send(&self.0)
            }

            #[cfg(test)]
            pub(crate) fn test_bytes(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

frame_api!(CredentialServiceRequestFrame);
frame_api!(CredentialServiceReplyFrame);
frame_api!(CredentialWriterBrokerHandoffFrame);
