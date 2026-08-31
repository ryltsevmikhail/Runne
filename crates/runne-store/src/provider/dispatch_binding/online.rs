use runne_provider::{CredentialVersionRef, ProviderId};

use super::{CredentialDispatchBinding, OnlineDispatchSeal};

/// Store-issued online binding. It deliberately has no clone or serialization
/// path: native loading and the post-materialization CAS receive disjoint,
/// privately constructed halves.
pub(crate) struct OnlineCredentialDispatchBinding {
    credential: CredentialDispatchBinding,
    provider: ProviderId,
    lifecycle_revision: u64,
    credential_fence: u64,
    launch_generation: u64,
}

pub(crate) struct OnlineEffectStartBinding {
    provider: ProviderId,
    active: CredentialVersionRef,
    lifecycle_revision: u64,
    credential_fence: u64,
    launch_generation: u64,
}

impl OnlineCredentialDispatchBinding {
    pub(crate) fn new(
        credential: CredentialDispatchBinding,
        lifecycle_revision: u64,
        credential_fence: u64,
        launch_generation: u64,
    ) -> Self {
        let provider = credential.version_ref().provider().clone();
        let active = credential.version_ref().clone();
        Self {
            provider: provider.clone(),
            credential: credential.with_online_seal(OnlineDispatchSeal::new(
                provider,
                active,
                lifecycle_revision,
                credential_fence,
                launch_generation,
            )),
            lifecycle_revision,
            credential_fence,
            launch_generation,
        }
    }

    pub(super) fn matches(&self, seal: &OnlineDispatchSeal) -> bool {
        seal.provider == self.provider
            && seal.active == *self.credential.version_ref()
            && seal.lifecycle_revision == self.lifecycle_revision
            && seal.credential_fence == self.credential_fence
            && seal.launch_generation == self.launch_generation
    }

    /// Moves the native-load capability and exact CAS tuple out once.
    pub(crate) fn split(self) -> (CredentialDispatchBinding, OnlineEffectStartBinding) {
        let active = self.credential.version_ref().clone();
        (
            self.credential,
            OnlineEffectStartBinding {
                provider: self.provider,
                active,
                lifecycle_revision: self.lifecycle_revision,
                credential_fence: self.credential_fence,
                launch_generation: self.launch_generation,
            },
        )
    }
}

impl OnlineEffectStartBinding {
    pub(crate) const fn provider(&self) -> &ProviderId {
        &self.provider
    }
    pub(crate) const fn active(&self) -> &CredentialVersionRef {
        &self.active
    }
    pub(crate) const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }
    pub(crate) const fn credential_fence(&self) -> u64 {
        self.credential_fence
    }
    pub(crate) const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }
}
