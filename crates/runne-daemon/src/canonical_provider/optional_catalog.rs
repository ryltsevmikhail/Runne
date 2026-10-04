use runne_application::provider::ProviderSecondaryProfileGrantSpec;
use runne_provider::ProviderId;
use runne_provider_openai::{OPENAI_RESPONSES_BACKGROUND_PROFILE_ID, OpenAiResponsesTextProfile};
use sha2::{Digest as _, Sha256};

use crate::config::{VerifiedFixedExternalConfig, external_config_path};
use crate::error::DaemonError;

const SOURCE: &[u8] =
    include_bytes!("../../../../docs/profiles/openai-responses-background-text-v1.json");
const DIGEST_DOMAIN: &[u8] = b"GOCODE_SECONDARY_PROFILE_CATALOG_V1\0";

/// Opaque evidence that the fixed owner-private file opted into the exact
/// compiled profile and bounded its independent budget.
#[derive(Clone)]
pub(crate) struct VerifiedSecondaryCatalog {
    spec: ProviderSecondaryProfileGrantSpec,
    digest: [u8; 32],
    authority_id: [u8; 16],
    db_path: String,
}

impl VerifiedSecondaryCatalog {
    #[cfg(test)]
    pub(super) fn from_test_spec(
        spec: ProviderSecondaryProfileGrantSpec,
        authority_id: [u8; 16],
        db_path: &str,
    ) -> Self {
        let digest = catalog_digest(
            &spec,
            authority_id,
            db_path,
            external_config_path().to_string_lossy().as_ref(),
        );
        Self {
            spec,
            digest,
            authority_id,
            db_path: db_path.to_owned(),
        }
    }

    pub(crate) fn from_fixed_source(
        source: &VerifiedFixedExternalConfig,
        authority_id: [u8; 16],
        expected_db_path: Option<&str>,
    ) -> Result<Option<Self>, DaemonError> {
        let config = source.snapshot();
        let Some(input) = config.secondary_profile_catalog.as_ref() else {
            return Ok(None);
        };
        let path = external_config_path();
        let provenance = config.provenance.get("secondary_profile_catalog");
        if authority_id == [0; 16]
            || expected_db_path.is_some_and(|expected| expected != config.db_path)
            || provenance.is_none_or(|field| {
                field.source != crate::config::Source::SystemFile
                    || field.path.as_deref() != path.to_str()
            })
        {
            return Err(invalid_catalog());
        }
        Self::compile(
            input,
            authority_id,
            &config.db_path,
            path.to_string_lossy().as_ref(),
        )
        .map(Some)
    }

    fn compile(
        input: &crate::config::SecondaryProfileCatalogConfig,
        authority_id: [u8; 16],
        db_path: &str,
        source_path: &str,
    ) -> Result<Self, DaemonError> {
        let profile =
            OpenAiResponsesTextProfile::from_json(SOURCE).map_err(|_| invalid_catalog())?;
        let profile_digest = digest_field(input.profile_digest())?;
        let pricing_digest = digest_field(input.pricing_revision_digest())?;
        if input.provider_id() != profile.provider_id()
            || input.profile_id() != profile.profile_id()
            || input.profile_id() != OPENAI_RESPONSES_BACKGROUND_PROFILE_ID
            || input.credential_realm() != profile.provider_id()
            || profile_digest != profile.profile_digest()
            || pricing_digest != profile.pricing_revision_digest()
            || !profile.is_background()
        {
            return Err(invalid_catalog());
        }
        let provider = ProviderId::new(profile.provider_id()).map_err(|_| invalid_catalog())?;
        let spec = ProviderSecondaryProfileGrantSpec::new(
            &provider,
            profile.profile_id(),
            profile.provider_id(),
            profile_digest,
            pricing_digest,
            input.token_budget_limit(),
            input.cost_budget_limit_micros(),
        )
        .map_err(|_| invalid_catalog())?;
        let digest = catalog_digest(&spec, authority_id, db_path, source_path);
        Ok(Self {
            spec,
            digest,
            authority_id,
            db_path: db_path.to_owned(),
        })
    }

    pub(crate) const fn spec(&self) -> &ProviderSecondaryProfileGrantSpec {
        &self.spec
    }
    pub(crate) const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) const fn authority_id(&self) -> [u8; 16] {
        self.authority_id
    }
    pub(crate) fn db_path(&self) -> &str {
        &self.db_path
    }
}

fn digest_field(value: &str) -> Result<[u8; 32], DaemonError> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(invalid_catalog)
}

fn catalog_digest(
    spec: &ProviderSecondaryProfileGrantSpec,
    authority_id: [u8; 16],
    db_path: &str,
    source_path: &str,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DIGEST_DOMAIN);
    hash.update(authority_id);
    hash.update((db_path.len() as u64).to_be_bytes());
    hash.update(db_path.as_bytes());
    hash.update((source_path.len() as u64).to_be_bytes());
    hash.update(source_path.as_bytes());
    hash.update(spec.provider_id().as_bytes());
    hash.update(spec.profile_id().as_bytes());
    hash.update(spec.credential_realm().as_bytes());
    hash.update(spec.profile_digest());
    hash.update(spec.pricing_revision_digest());
    hash.update(spec.token_budget_limit().to_be_bytes());
    hash.update(spec.cost_budget_limit_micros().to_be_bytes());
    hash.finalize().into()
}

fn invalid_catalog() -> DaemonError {
    DaemonError::Config("secondary provider catalog is invalid".into())
}

#[cfg(test)]
#[path = "optional_catalog_tests.rs"]
mod tests;
