use crate::canonical_provider::VerifiedSecondaryCatalog;
use crate::error::DaemonError;
use runne_provider::ProviderRecoveryCapabilities;
use runne_provider_openai::OpenAiResponsesTextProfile;

const PROFILE: &[u8] =
    include_bytes!("../../../../../docs/profiles/openai-responses-background-text-v1.json");

pub(in crate::canonical_provider) struct SecondaryEffectsMetadata {
    provider_id: String,
    credential_realm: String,
    profile_id: String,
    profile_digest: [u8; 32],
    pricing_digest: [u8; 32],
    catalog_digest: [u8; 32],
    catalog_authority_id: [u8; 16],
    db_path: String,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    capabilities: ProviderRecoveryCapabilities,
}

impl SecondaryEffectsMetadata {
    pub(in crate::canonical_provider) fn from_catalog(
        catalog: Option<&VerifiedSecondaryCatalog>,
        db_path: &str,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
        override_capabilities: Option<ProviderRecoveryCapabilities>,
    ) -> Result<Option<Self>, DaemonError> {
        let Some(catalog) = catalog else {
            return Ok(None);
        };
        let profile =
            OpenAiResponsesTextProfile::from_json(PROFILE).map_err(|_| invalid_metadata())?;
        let spec = catalog.spec();
        if catalog.db_path() != db_path
            || catalog.authority_id() != runtime_authority_id
            || catalog.digest() == [0; 32]
            || spec.provider_id() != profile.provider_id()
            || spec.credential_realm() != profile.provider_id()
            || spec.profile_id() != profile.profile_id()
            || spec.profile_digest() != profile.profile_digest()
            || spec.pricing_revision_digest() != profile.pricing_revision_digest()
            || !profile.is_background()
            || database_generation == 0
        {
            return Err(invalid_metadata());
        }
        let capabilities = override_capabilities
            .unwrap_or_else(runne_daemon_openai_effect::background_recovery_capabilities);
        if capabilities.stream_resume || (!capabilities.status_check && !capabilities.remote_cancel)
        {
            return Err(invalid_metadata());
        }
        Ok(Some(Self {
            provider_id: spec.provider_id().to_owned(),
            credential_realm: spec.credential_realm().to_owned(),
            profile_id: spec.profile_id().to_owned(),
            profile_digest: spec.profile_digest(),
            pricing_digest: spec.pricing_revision_digest(),
            catalog_digest: catalog.digest(),
            catalog_authority_id: catalog.authority_id(),
            db_path: catalog.db_path().to_owned(),
            runtime_authority_id,
            database_generation,
            capabilities,
        }))
    }

    pub(in crate::canonical_provider) fn matches(
        &self,
        binding: &runne_application::provider::ProviderRemoteAttemptBinding,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
    ) -> bool {
        self.catalog_digest != [0; 32]
            && !self.db_path.is_empty()
            && self.catalog_authority_id == runtime_authority_id
            && self.runtime_authority_id == runtime_authority_id
            && self.database_generation == database_generation
            && binding.runtime_authority_id == runtime_authority_id
            && binding.database_generation == database_generation
            && binding.provider_id == self.provider_id
            && binding.credential_realm == self.credential_realm
            && binding.profile_id == self.profile_id
            && binding.profile_digest == self.profile_digest
            && binding.pricing_digest == self.pricing_digest
    }

    pub(in crate::canonical_provider) const fn capabilities(&self) -> ProviderRecoveryCapabilities {
        self.capabilities
    }
}

fn invalid_metadata() -> DaemonError {
    DaemonError::Bootstrap("secondary provider effects metadata unavailable".into())
}
