//! Builder errors: bounded, typed refusal surface (MANIFEST_TOOLING
//! §Interface). Debug names are contract surface.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuilderError {
    /// Artifact stream could not be read at all.
    SourceUnreadable,
    /// Not a supported GGUF image (magic/version) or architecture
    /// outside the v1 compatibility graph.
    UnsupportedFormat,
    /// GGUF parses badly or lacks evidence the builder cannot invent
    /// (embedded tokenizer, context length).
    ArtifactUnparseable,
    /// No embedded template and no user template file.
    TemplateMissing,
    /// License or provenance absent — never synthesized.
    LicenseMissing,
    /// Same inputs produced different bytes, or user tried to lower
    /// `minCompatibleRuntime` below the builder's contract version.
    DeterminismViolation,
}

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::SourceUnreadable => "artifact source unreadable",
            Self::UnsupportedFormat => "unsupported GGUF format or architecture",
            Self::ArtifactUnparseable => "artifact unparseable or evidence missing",
            Self::TemplateMissing => "no embedded template and no user template",
            Self::LicenseMissing => "license or provenance must be user-supplied",
            Self::DeterminismViolation => "determinism contract violated",
        };
        write!(f, "{text}")
    }
}

impl std::error::Error for BuilderError {}
