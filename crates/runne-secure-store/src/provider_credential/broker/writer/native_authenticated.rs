use std::os::unix::net::UnixStream;
use std::sync::Arc;

use runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession;
use runne_provider::{
    BrokerChannelBinding, CredentialAuthorityPair, CredentialWriterClaimIssuer,
    PendingCredentialIssueTicketV1,
};

use super::native::{NativeBrokeredProviderCredentialWriter, NativeProviderCredentialWriters};
use super::{BrokeredProviderCredentialWriter, BrokeredProviderCredentialWriterAdapter};
use crate::{NativeProviderCredentialStore, ProviderCredentialAccessPolicy, SecureStoreError};

pub(super) struct AuthenticatedNativeWriterParts {
    control: UnixStream,
    channel: BrokerChannelBinding,
    ticket: PendingCredentialIssueTicketV1,
}

impl NativeProviderCredentialWriters {
    /// Constructs the only production native writer from one authenticated
    /// packaged-writer session.
    ///
    /// # Errors
    ///
    /// Rejects incomplete authentication resources or executable identities
    /// that cannot be measured again for native-store admission.
    pub fn from_authenticated_session(
        session: AuthenticatedProviderCredentialWriterSession,
    ) -> Result<Self, SecureStoreError> {
        let (claim, effect) = session.split();
        let (issuer, control, channel, ticket) = claim
            .into_macos_claim_parts()
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        let (effects, writer_path, reader_path) = effect
            .into_macos_effect_parts()
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        let access = ProviderCredentialAccessPolicy::new(&writer_path, &reader_path)?;
        let (lifecycle, native_authority) = CredentialAuthorityPair::new().split();
        let native = NativeProviderCredentialStore::new_versioned(native_authority);
        let writer = NativeBrokeredProviderCredentialWriter::new(lifecycle, native);

        Ok(Self {
            issuer,
            writer: Arc::new(BrokeredProviderCredentialWriterAdapter::new(
                effects, writer, access,
            )),
            authenticated: Some(AuthenticatedNativeWriterParts {
                control,
                channel,
                ticket,
            }),
        })
    }

    /// Consumes the admitted bundle into its authenticated claim resources and
    /// its only effect-capable writer port.
    ///
    /// # Errors
    ///
    /// Rejects test-only or otherwise unauthenticated bundles.
    #[doc(hidden)]
    #[allow(
        clippy::type_complexity,
        reason = "the CLI broker keeps all move-only admission resources together"
    )]
    pub fn into_authenticated_parts(
        self,
    ) -> Result<
        (
            UnixStream,
            BrokerChannelBinding,
            PendingCredentialIssueTicketV1,
            CredentialWriterClaimIssuer,
            Arc<dyn BrokeredProviderCredentialWriter>,
        ),
        SecureStoreError,
    > {
        let authenticated = self
            .authenticated
            .ok_or(SecureStoreError::CredentialAccessDenied)?;
        Ok((
            authenticated.control,
            authenticated.channel,
            authenticated.ticket,
            self.issuer,
            self.writer,
        ))
    }
}
