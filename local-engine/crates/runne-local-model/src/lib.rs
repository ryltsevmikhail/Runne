//! runne-local-model: immutable `ModelManifestV1`, canonical JCS identity
//! and the bounded GGUF inspection — the model-identity crate of the
//! Runne Local Engine.

pub mod builder;
pub mod builder_error;
pub mod canonical;
pub mod error;
pub mod gguf;
pub mod gguf_limits;
mod gguf_metadata;
pub mod identity;
pub mod manifest;
pub mod specs;
pub mod tokenizer_quote;

pub use builder::{
    BUILDER_CONTRACT_VERSION, CandidateManifest, UserSupplied, build_candidate_manifest,
};
pub use builder_error::BuilderError;
pub use canonical::{Canonicalized, canonicalize_strict};
pub use error::ManifestError;
pub use gguf::GgufInspection;
pub use identity::{ManifestDigest, VerifiedModelManifest, compute_digest, manifest_id};
pub use manifest::ModelManifestV1;
pub use specs::{
    ArtifactDigest, BackendProfileId, Capabilities, ChatTemplateRevision, ToolProtocolRevision,
};
pub use tokenizer_quote::{QuoteError, QuoteRevision, revision_from_name, token_quote};
