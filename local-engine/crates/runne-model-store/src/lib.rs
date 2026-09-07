//! runne-model-store: durable model catalog and immutable artifact store
//! (Plan Task 4). The catalog is installation metadata, never TaskRun
//! authority.

pub mod artifact;
pub mod catalog;
pub mod error;
pub mod import;
pub mod recovery;
pub mod remove;
pub mod schema;
pub mod upload;

pub use artifact::{BlobStore, StagedBlob};
pub use catalog::{
    DiscardDisposition, ImportCandidate, InstalledModel, LicenseAcceptance, MatrixBinding,
    ModelArtifactStore, RemoveDisposition, catalog_now,
};
pub use error::StoreError;
pub use recovery::RecoveryReport;
pub use schema::SCHEMA_VERSION;
