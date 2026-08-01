/// Exact provider/model/revision binding for historical execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelRef {
    provider_id: ProviderId,
    model_id: String,
    revision: String,
}

#[derive(Deserialize)]
struct RawModelRef {
    provider_id: String,
    model_id: String,
    revision: String,
}

impl<'de> Deserialize<'de> for ModelRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawModelRef::deserialize(deserializer)?;
        let provider_id =
            ProviderId::new(raw.provider_id).map_err(<D::Error as serde::de::Error>::custom)?;

        ModelRef::new(provider_id, raw.model_id, raw.revision)
            .map_err(<D::Error as serde::de::Error>::custom)
    }
}

impl ModelRef {
    /// Constructs an exact bounded model reference.
    pub fn new(
        provider_id: ProviderId,
        model_id: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, InvalidProviderId> {
        Ok(Self {
            provider_id,
            model_id: bounded_identifier(model_id.into())?,
            revision: bounded_identifier(revision.into())?,
        })
    }

    /// Returns the provider identity.
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the model identity.
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// Returns the immutable model revision.
    pub fn revision(&self) -> &str {
        &self.revision
    }
}
