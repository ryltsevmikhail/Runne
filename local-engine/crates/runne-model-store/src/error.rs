//! Store errors (typed, sanitized; Debug names are contract surface).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    Io(String),
    Sqlite(String),
    Schema(String),
    NonRegularFile,
    DigestMismatch,
    LengthMismatch,
    OffsetMismatch { expected: u64 },
    PrefixMismatch,
    SessionExpired,
    SessionMissing,
    CandidateMissing,
    CandidateNotStaged,
    AdmissionConflict,
    LicenseMismatch,
    UnqualifiedProfile,
    ActiveReferences,
    BlobMissing,
    MalformedManifest,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(m) => write!(f, "store io: {m}"),
            Self::Sqlite(m) => write!(f, "store db: {m}"),
            Self::Schema(m) => write!(f, "store schema: {m}"),
            Self::NonRegularFile => write!(f, "source is not a regular file"),
            Self::DigestMismatch => write!(f, "artifact digest mismatch"),
            Self::LengthMismatch => write!(f, "artifact length mismatch"),
            Self::OffsetMismatch { expected } => {
                write!(f, "upload offset mismatch: expected {expected}")
            }
            Self::PrefixMismatch => write!(f, "committed hash-prefix mismatch on resume"),
            Self::SessionExpired => write!(f, "upload session expired"),
            Self::SessionMissing => write!(f, "upload session missing"),
            Self::CandidateMissing => write!(f, "import candidate missing"),
            Self::CandidateNotStaged => write!(f, "candidate is not in staged state"),
            Self::AdmissionConflict => write!(f, "admission identity conflict"),
            Self::LicenseMismatch => write!(f, "license acceptance mismatch"),
            Self::UnqualifiedProfile => write!(f, "no qualified backend profile"),
            Self::ActiveReferences => write!(f, "installation has active references"),
            Self::BlobMissing => write!(f, "content-addressed blob missing"),
            Self::MalformedManifest => write!(f, "malformed manifest"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err.to_string())
    }
}

impl From<runne_local_model::ManifestError> for StoreError {
    fn from(_: runne_local_model::ManifestError) -> Self {
        Self::MalformedManifest
    }
}
