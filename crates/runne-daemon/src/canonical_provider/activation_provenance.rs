use runne_api::ProviderActivationBindingV1;
use runne_application::provider::ProviderLeaseBindingKind;
use sha2::{Digest as _, Sha256};

use crate::application::VerifiedOwnerPrivateConfig;
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
use crate::protected_activation::VerifiedProtectedApplicationStart;

const DOMAIN: &[u8] = b"GOCODE_DAEMON_ACTIVATION_BINDING_V1\0";

#[derive(Clone, Copy)]
pub(crate) struct DaemonActivationProvenance {
    kind: ProviderLeaseBindingKind,
    digest: [u8; 32],
}

impl DaemonActivationProvenance {
    #[cfg(all(any(unix, windows), feature = "desktop-protected"))]
    pub(crate) fn from_verified_protected_launch(
        start: &VerifiedProtectedApplicationStart,
    ) -> Self {
        Self {
            kind: ProviderLeaseBindingKind::ProtectedV2,
            digest: digest(
                ProviderLeaseBindingKind::ProtectedV2,
                start.provider_activation().binding(),
                start.authority_id(),
                None,
            ),
        }
    }
    pub(crate) fn from_verified_owner_private_config(config: &VerifiedOwnerPrivateConfig) -> Self {
        Self {
            kind: ProviderLeaseBindingKind::ExternalOwnerPrivate,
            digest: digest(
                ProviderLeaseBindingKind::ExternalOwnerPrivate,
                config.provider_activation().binding(),
                config.authority_id(),
                Some(config.config_digest()),
            ),
        }
    }
    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    pub(super) fn for_terminal_adoption(
        binding: &ProviderActivationBindingV1,
        authority: [u8; 16],
    ) -> Self {
        Self {
            kind: ProviderLeaseBindingKind::ProtectedV2,
            digest: digest(
                ProviderLeaseBindingKind::ProtectedV2,
                binding,
                authority,
                None,
            ),
        }
    }

    pub(super) fn for_cli_upgrade(
        config: &crate::config::ConfigurationSnapshot,
        authority: [u8; 16],
    ) -> Self {
        Self {
            kind: ProviderLeaseBindingKind::ExternalOwnerPrivate,
            digest: digest(
                ProviderLeaseBindingKind::ExternalOwnerPrivate,
                config.provider_activation.binding(),
                authority,
                Some(&config.digest),
            ),
        }
    }
    pub(super) const fn kind(&self) -> ProviderLeaseBindingKind {
        self.kind
    }
    pub(super) const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) const fn is_protected(&self) -> bool {
        matches!(self.kind, ProviderLeaseBindingKind::ProtectedV2)
    }
}

fn digest(
    kind: ProviderLeaseBindingKind,
    binding: &ProviderActivationBindingV1,
    authority: [u8; 16],
    config: Option<&str>,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(kind.code().as_bytes());
    h.update(authority);
    h.update(binding.mode().as_str().as_bytes());
    h.update(binding.profile_id().as_bytes());
    h.update(binding.profile_digest());
    if let Some(value) = config {
        h.update(b"external-owner-private\0");
        h.update(value.as_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests;
