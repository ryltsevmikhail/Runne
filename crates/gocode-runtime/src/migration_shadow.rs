//! Capability-free simulated-shadow execution.

use std::collections::BTreeMap;

use gocode_application::migration::{
    ports::{
        SanitizedShadowInput, ShadowDiffReport, ShadowExecutionError, ShadowExecutionPort,
        ShadowSemanticClass,
    },
    types::ArtifactDigest,
};
use sha2::{Digest, Sha256};

const MAX_SHADOW_ID_BYTES: usize = 128;
const MAX_REDACTED_INPUT_BYTES: usize = 1_048_576;
const REDACTED_TRANSLATION_PREFIX: &[u8] = b"gocode-shadow-redacted\x01";

/// Immutable fixture catalog available to a pure shadow executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedFixtureCatalog {
    candidate_digests: BTreeMap<String, ArtifactDigest>,
}

impl RecordedFixtureCatalog {
    /// Validate and construct an immutable catalog.
    pub fn new(
        entries: impl IntoIterator<Item = (String, ArtifactDigest)>,
    ) -> Result<Self, ShadowExecutionError> {
        let mut candidate_digests = BTreeMap::new();
        for (fixture_id, digest) in entries {
            validate_identifier(&fixture_id)?;
            if candidate_digests.insert(fixture_id, digest).is_some() {
                return Err(ShadowExecutionError::InvalidInput);
            }
        }
        Ok(Self { candidate_digests })
    }

    fn candidate_digest(&self, fixture_id: &str) -> Option<ArtifactDigest> {
        self.candidate_digests.get(fixture_id).copied()
    }
}

/// Pure, capability-free implementation of the simulated-shadow port.
#[derive(Debug, Clone)]
pub struct PureShadowExecutor {
    fixtures: RecordedFixtureCatalog,
}

impl PureShadowExecutor {
    /// Construct an executor from an immutable fixture catalog.
    pub fn new(fixtures: RecordedFixtureCatalog) -> Self {
        Self { fixtures }
    }

    /// Canonical writes are structurally impossible for this executor.
    pub const fn canonical_write_count(&self) -> u64 {
        0
    }

    /// External dispatch is structurally impossible for this executor.
    pub const fn external_dispatch_count(&self) -> u64 {
        0
    }
}

impl ShadowExecutionPort for PureShadowExecutor {
    fn evaluate(
        &self,
        input: SanitizedShadowInput,
    ) -> Result<ShadowDiffReport, ShadowExecutionError> {
        let (source_digest, candidate_digest) = match input {
            SanitizedShadowInput::RecordedFixture {
                fixture_id,
                source_digest,
            } => {
                validate_identifier(&fixture_id)?;
                let candidate_digest = self
                    .fixtures
                    .candidate_digest(&fixture_id)
                    .ok_or(ShadowExecutionError::FixtureNotFound)?;
                (source_digest, candidate_digest)
            }
            SanitizedShadowInput::RedactedTranslation {
                operation_id,
                canonical_bytes,
            } => {
                validate_identifier(&operation_id)?;
                if canonical_bytes.is_empty() || canonical_bytes.len() > MAX_REDACTED_INPUT_BYTES {
                    return Err(ShadowExecutionError::InvalidInput);
                }
                let source_digest = redacted_translation_digest(&operation_id, &canonical_bytes)?;
                let candidate_digest = self
                    .fixtures
                    .candidate_digest(&operation_id)
                    .ok_or(ShadowExecutionError::FixtureNotFound)?;
                (source_digest, candidate_digest)
            }
            SanitizedShadowInput::ExternalEffect { .. } => {
                return Err(ShadowExecutionError::ExternalEffectForbidden);
            }
        };
        let semantic_class = if source_digest == candidate_digest {
            ShadowSemanticClass::Exact
        } else {
            ShadowSemanticClass::Divergent
        };
        Ok(ShadowDiffReport {
            source_digest,
            candidate_digest,
            semantic_class,
            client_acknowledgement: None,
        })
    }
}

fn redacted_translation_digest(
    operation_id: &str,
    canonical_bytes: &[u8],
) -> Result<ArtifactDigest, ShadowExecutionError> {
    let operation_length =
        u16::try_from(operation_id.len()).map_err(|_| ShadowExecutionError::InvalidInput)?;
    let input_length =
        u64::try_from(canonical_bytes.len()).map_err(|_| ShadowExecutionError::InvalidInput)?;
    let mut hasher = Sha256::new();
    hasher.update(REDACTED_TRANSLATION_PREFIX);
    hasher.update(operation_length.to_be_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update(input_length.to_be_bytes());
    hasher.update(canonical_bytes);
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn validate_identifier(value: &str) -> Result<(), ShadowExecutionError> {
    if value.is_empty()
        || value.len() > MAX_SHADOW_ID_BYTES
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        Err(ShadowExecutionError::InvalidInput)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use gocode_application::migration::{
        ports::{
            SanitizedShadowInput, ShadowExecutionError, ShadowExecutionPort, ShadowSemanticClass,
        },
        types::ArtifactDigest,
    };

    use super::{PureShadowExecutor, RecordedFixtureCatalog};

    #[test]
    fn shadow_rejects_unsanitized_or_effectful_input() {
        let executor = PureShadowExecutor::new(recorded_fixture_catalog());

        assert_eq!(
            executor.evaluate(SanitizedShadowInput::external_effect("provider.call")),
            Err(ShadowExecutionError::ExternalEffectForbidden)
        );
        assert_eq!(executor.canonical_write_count(), 0);
        assert_eq!(executor.external_dispatch_count(), 0);
    }

    #[test]
    fn shadow_diff_is_deterministic_and_cannot_acknowledge_client() {
        let executor = PureShadowExecutor::new(recorded_fixture_catalog());

        let first = executor.evaluate(golden_shadow_input()).unwrap();
        let second = executor.evaluate(golden_shadow_input()).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.semantic_class, ShadowSemanticClass::Exact);
        assert_eq!(first.client_acknowledgement, None);
        assert_eq!(executor.canonical_write_count(), 0);
        assert_eq!(executor.external_dispatch_count(), 0);
    }

    #[test]
    fn redacted_translation_compares_against_independent_candidate_digest() {
        let executor = PureShadowExecutor::new(recorded_fixture_catalog());

        let report = executor
            .evaluate(SanitizedShadowInput::RedactedTranslation {
                operation_id: "operation-1".to_owned(),
                canonical_bytes: b"baseline-result".to_vec(),
            })
            .unwrap();

        assert_eq!(report.candidate_digest, ArtifactDigest::from_bytes([3; 32]));
        assert_eq!(report.semantic_class, ShadowSemanticClass::Divergent);
        assert_eq!(report.client_acknowledgement, None);
    }

    fn recorded_fixture_catalog() -> RecordedFixtureCatalog {
        RecordedFixtureCatalog::new([
            ("fixture-1".to_owned(), ArtifactDigest::from_bytes([2; 32])),
            (
                "operation-1".to_owned(),
                ArtifactDigest::from_bytes([3; 32]),
            ),
        ])
        .unwrap()
    }

    fn golden_shadow_input() -> SanitizedShadowInput {
        SanitizedShadowInput::RecordedFixture {
            fixture_id: "fixture-1".to_owned(),
            source_digest: ArtifactDigest::from_bytes([2; 32]),
        }
    }
}
