use std::os::unix::net::UnixStream;
use std::sync::Arc;

/// Linux route has no XPC credential service: the in-process legacy native
/// writer is the only effect route, so the service configuration type is an
/// unreachable placeholder here.
#[cfg(target_os = "linux")]
type CredentialServiceEndpointConfiguration = std::convert::Infallible;

#[cfg(target_os = "macos")]
use runne_macos_xpc::{
    CredentialServiceEndpointConfiguration, CredentialServiceEndpointRole,
    CredentialServicePeerRequirement, CredentialServiceXpcError,
};
use runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession;
use runne_provider::{
    BrokerChannelBinding, CredentialAuthorityPair, CredentialWriterClaimIssuer,
    PendingCredentialIssueTicketV1,
};

use super::legacy_source::{
    BrokeredProviderCredentialLegacySource, NativeProviderCredentialLegacySource,
};
use super::native::{
    NativeBrokeredProviderCredentialWriter, NativeProviderCredentialEffectRoute,
    NativeProviderCredentialWriters,
};
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
        #[cfg(target_os = "macos")]
        let (issuer, control, channel, ticket, content_pin_token) = {
            let (issuer, control, channel, ticket, release) = claim
                .into_macos_claim_parts()
                .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
            let _ = &effect;
            (issuer, control, channel, ticket, release)
        };
        #[cfg(target_os = "linux")]
        let (issuer, control, channel, ticket) = {
            // Linux: the ALREADY-BOUND ticket from the closed authority
            // session (binding happened inside the authenticated receiver);
            // no raw record or arrays ever reach the store.
            let (issuer, control, channel, ticket) = claim
                .into_linux_claim_parts()
                .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
            (issuer, control, channel, ticket)
        };
        #[cfg(target_os = "macos")]
        let ticket = ticket
            .bind_verified_qualification_release(&release)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        #[cfg(target_os = "macos")]
        let (effects, writer_path, reader_path) = effect
            .into_macos_effect_parts()
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        #[cfg(target_os = "macos")]
        let credential_service = release
            .native_enrollment_tuple_v3()
            .map(|tuple| {
                writer_endpoint_configuration(
                    tuple.credential_service_identity(),
                    tuple.writer_identity(),
                )
            })
            .transpose()
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        #[cfg(target_os = "linux")]
        let (effects, writer_path, reader_path) = effect
            .into_linux_effect_parts()
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        #[cfg(target_os = "linux")]
        // Linux route: no XPC credential service — the in-process legacy
        // native writer is the only effect route; the release pin already
        // rides the attestation claims, so no release binding is applied.
        let credential_service: Option<CredentialServiceEndpointConfiguration> = None;
        #[cfg(feature = "local-native-enrollment-test")]
        let credential_service = match credential_service {
            Some(configuration) => Some(configuration),
            None => local_writer_endpoint_configuration(&writer_path)
                .map_err(|_| SecureStoreError::CredentialAccessDenied)?,
        };
        let verifier = ticket
            .legacy_read_verifier(&effects, &channel)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        let effect_route = build_effect_route(
            effects,
            credential_service,
            |effects| {
                let access = ProviderCredentialAccessPolicy::new(&writer_path, &reader_path)?;
                let (lifecycle, native_authority) = CredentialAuthorityPair::new().split();
                let native = NativeProviderCredentialStore::new_versioned(native_authority);
                let writer = NativeBrokeredProviderCredentialWriter::new(lifecycle, native);
                Ok(Arc::new(BrokeredProviderCredentialWriterAdapter::new(
                    effects, writer, access,
                ))
                    as Arc<dyn BrokeredProviderCredentialWriter>)
            },
            || {
                let access = ProviderCredentialAccessPolicy::new(&writer_path, &reader_path)?;
                Ok(Arc::new(NativeProviderCredentialLegacySource::new(
                    NativeProviderCredentialStore::new(),
                    access,
                    verifier,
                ))
                    as Arc<dyn BrokeredProviderCredentialLegacySource>)
            },
        )?;

        Ok(Self {
            issuer,
            effect_route,
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
            NativeProviderCredentialEffectRoute,
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
            self.effect_route,
        ))
    }
}

fn build_effect_route(
    effects: runne_provider::CredentialWriterEffectAuthority,
    credential_service: Option<CredentialServiceEndpointConfiguration>,
    legacy: impl FnOnce(
        runne_provider::CredentialWriterEffectAuthority,
    ) -> Result<Arc<dyn BrokeredProviderCredentialWriter>, SecureStoreError>,
    legacy_source: impl FnOnce() -> Result<
        Arc<dyn BrokeredProviderCredentialLegacySource>,
        SecureStoreError,
    >,
) -> Result<NativeProviderCredentialEffectRoute, SecureStoreError> {
    match credential_service {
        #[cfg(target_os = "macos")]
        Some(configuration) => Ok(NativeProviderCredentialEffectRoute::CredentialService {
            effects,
            configuration,
            legacy: legacy_source()?,
        }),
        #[cfg(target_os = "macos")]
        None if cfg!(feature = "local-native-enrollment-test") => {
            legacy(effects).map(NativeProviderCredentialEffectRoute::Legacy)
        }
        #[cfg(target_os = "macos")]
        None => Err(SecureStoreError::UnsupportedSecureStoreBackend),
        #[cfg(target_os = "linux")]
        None => legacy(effects).map(NativeProviderCredentialEffectRoute::Legacy),
    }
}

#[cfg(target_os = "macos")]
fn writer_endpoint_configuration(
    service: &runne_api::MacOsCodeIdentityExpectationV1,
    writer: &runne_api::MacOsCodeIdentityExpectationV1,
) -> Result<CredentialServiceEndpointConfiguration, CredentialServiceXpcError> {
    CredentialServiceEndpointConfiguration::new(
        CredentialServiceEndpointRole::Writer,
        CredentialServiceEndpointRole::Writer.endpoint_name(),
        requirement(service)?,
        requirement(writer)?,
    )
}

#[cfg(target_os = "macos")]
fn requirement(
    identity: &runne_api::MacOsCodeIdentityExpectationV1,
) -> Result<CredentialServicePeerRequirement, CredentialServiceXpcError> {
    CredentialServicePeerRequirement::new(format!(
        "identifier \"{}\" and anchor apple generic and certificate leaf[subject.OU] = \"{}\" and cdhash H\"{}\"",
        identity.identifier(),
        identity.team_identifier(),
        identity.cdhash(),
    ))
}

#[cfg(feature = "local-native-enrollment-test")]
#[cfg(target_os = "macos")]
fn local_writer_endpoint_configuration(
    writer: &std::path::Path,
) -> Result<Option<CredentialServiceEndpointConfiguration>, CredentialServiceXpcError> {
    if !runne_api::test_support::local_credential_service_fixture_enabled() {
        return Ok(None);
    }
    let root = std::fs::canonicalize(
        std::env::var_os("RUNNE_SLICE_E_FIXTURE_ROOT")
            .ok_or(CredentialServiceXpcError::Rejected)?,
    )
    .map_err(|_| CredentialServiceXpcError::Rejected)?;
    let writer = std::fs::canonicalize(writer).map_err(|_| CredentialServiceXpcError::Rejected)?;
    if writer != root.join("Runne.app/Contents/MacOS/runne") {
        return Err(CredentialServiceXpcError::Rejected);
    }
    let service = root.join(
        "Runne.app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service",
    );
    CredentialServiceEndpointConfiguration::new(
        CredentialServiceEndpointRole::Writer,
        CredentialServiceEndpointRole::Writer.endpoint_name(),
        local_requirement(&service, "dev.runne.slice-e.credential-service")?,
        local_requirement(&writer, "dev.runne.slice-e.writer")?,
    )
    .map(Some)
}

#[cfg(feature = "local-native-enrollment-test")]
#[cfg(target_os = "macos")]
fn local_requirement(
    path: &std::path::Path,
    expected_identifier: &str,
) -> Result<CredentialServicePeerRequirement, CredentialServiceXpcError> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "-r", "-", "--"])
        .arg(path)
        .output()
        .map_err(|_| CredentialServiceXpcError::Unavailable)?;
    if !output.status.success() {
        return Err(CredentialServiceXpcError::Rejected);
    }
    let requirement = std::str::from_utf8(&output.stdout)
        .map_err(|_| CredentialServiceXpcError::Rejected)?
        .lines()
        .find_map(|line| {
            line.strip_prefix("designated => ")
                .or_else(|| line.strip_prefix("# designated => "))
        })
        .ok_or(CredentialServiceXpcError::Rejected)?;
    CredentialServicePeerRequirement::from_local_designated_requirement(
        expected_identifier,
        requirement,
    )
}

#[cfg(test)]
#[path = "native_route_tests.rs"]
mod native_route_tests;

#[cfg(test)]
#[path = "native_authenticated_tests.rs"]
mod tests;
