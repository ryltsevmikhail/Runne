//! Immutable `ModelManifestV1`: exact field names per
//! docs/03-subsystems/local-engine/MODEL_MANIFEST.md, bounded sizes,
//! private fields with immutable accessors, typed validation.

use crate::error::ManifestError;
use crate::specs::{
    ArtifactDigest, Capabilities, ChatTemplateSpec, Compatibility, HardwareRequirements,
    ProvenanceSpec, TokenizerSpec, ToolProtocolSpec, check_digest, check_str,
};
use serde::Deserialize;

const MAX_ARTIFACTS: usize = 32;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactRef {
    pub(crate) role: String,
    pub(crate) digest: ArtifactDigest,
    pub(crate) byte_length: u64,
    pub(crate) content_type: String,
}

impl ArtifactRef {
    pub fn role(&self) -> &str {
        &self.role
    }
    pub fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }
    pub fn content_type(&self) -> &str {
        &self.content_type
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModelManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub(crate) schema_version: String,
    #[serde(rename = "modelID")]
    pub(crate) model_id: String,
    #[serde(rename = "modelRevision")]
    pub(crate) model_revision: String,
    pub(crate) format: String,
    pub(crate) artifacts: Vec<ArtifactRef>,
    pub(crate) tokenizer: TokenizerSpec,
    #[serde(rename = "chatTemplate")]
    pub(crate) chat_template: ChatTemplateSpec,
    #[serde(
        rename = "toolProtocol",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) tool_protocol: Option<ToolProtocolSpec>,
    pub(crate) license: String,
    pub(crate) provenance: ProvenanceSpec,
    pub(crate) capabilities: Capabilities,
    #[serde(rename = "hardwareRequirements")]
    pub(crate) hardware_requirements: HardwareRequirements,
    pub(crate) compatibility: Compatibility,
    #[serde(rename = "minCompatibleRuntime")]
    pub(crate) min_compatible_runtime: String,
    #[serde(rename = "manifestDigest")]
    pub(crate) manifest_digest: String,
}

impl ModelManifestV1 {
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }
    pub fn model_id(&self) -> &str {
        &self.model_id
    }
    pub fn model_revision(&self) -> &str {
        &self.model_revision
    }
    pub fn format(&self) -> &str {
        &self.format
    }
    pub fn artifacts(&self) -> &[ArtifactRef] {
        &self.artifacts
    }
    pub fn tokenizer(&self) -> &TokenizerSpec {
        &self.tokenizer
    }
    pub fn chat_template(&self) -> &ChatTemplateSpec {
        &self.chat_template
    }
    pub fn tool_protocol(&self) -> Option<&ToolProtocolSpec> {
        self.tool_protocol.as_ref()
    }
    pub fn license(&self) -> &str {
        &self.license
    }
    pub fn provenance(&self) -> &ProvenanceSpec {
        &self.provenance
    }
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
    pub fn hardware_requirements(&self) -> &HardwareRequirements {
        &self.hardware_requirements
    }
    pub fn compatibility(&self) -> &Compatibility {
        &self.compatibility
    }
    pub fn min_compatible_runtime(&self) -> &str {
        &self.min_compatible_runtime
    }

    /// Typed validation beyond serde: names, digest formats, bounds,
    /// duplicate-free modalities.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != "ModelManifestV1" {
            return Err(ManifestError::Schema(format!(
                "unsupported schemaVersion {}",
                self.schema_version
            )));
        }
        check_str("modelID", &self.model_id)?;
        check_str("modelRevision", &self.model_revision)?;
        check_str("format", &self.format)?;
        if self.format != "GGUF" {
            return Err(ManifestError::Schema(format!(
                "unsupported format {}",
                self.format
            )));
        }
        if self.artifacts.is_empty() || self.artifacts.len() > MAX_ARTIFACTS {
            return Err(ManifestError::Schema("artifacts: empty or too many".into()));
        }
        for artifact in &self.artifacts {
            check_str("artifact.role", &artifact.role)?;
            check_str("artifact.contentType", &artifact.content_type)?;
        }
        check_digest("tokenizer.configDigest", &self.tokenizer.config_digest)?;
        check_digest(
            "chatTemplate.sourceDigest",
            &self.chat_template.source_digest,
        )?;
        if let Some(tp) = &self.tool_protocol {
            check_digest("toolProtocol.schemaDigest", &tp.schema_digest)?;
        }
        check_digest("provenance.sourceDigest", &self.provenance.source_digest)?;
        if self.capabilities.modalities.len() > crate::specs::MAX_MODALITIES {
            return Err(ManifestError::Schema("modalities: too many".into()));
        }
        let mut seen = std::collections::BTreeSet::new();
        for m in &self.capabilities.modalities {
            check_str("modality", m)?;
            if !seen.insert(m.as_str()) {
                return Err(ManifestError::Schema(format!("duplicate modality {m}")));
            }
        }
        if self.compatibility.backend_profiles.is_empty()
            || self.compatibility.backend_profiles.len() > crate::specs::MAX_PROFILES
        {
            return Err(ManifestError::Schema(
                "backendProfiles: empty or too many".into(),
            ));
        }
        for profile in &self.compatibility.backend_profiles {
            check_str("backendProfile.id", &profile.id)?;
            check_str("backendProfile.revision", &profile.revision)?;
        }
        check_str("license", &self.license)?;
        check_str("minCompatibleRuntime", &self.min_compatible_runtime)?;
        Ok(())
    }
}
