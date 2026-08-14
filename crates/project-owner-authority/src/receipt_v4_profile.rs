//! Exact raw-document profile for V4 promotion bootstrap.

/// Exact raw-document binding admitted by the V4 promotion-bootstrap profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedDocument {
    pub(crate) path: &'static str,
    pub(crate) mode: &'static str,
    pub(crate) blob_oid: &'static str,
    pub(crate) content_sha256: &'static str,
    pub(crate) byte_length: u64,
    pub(crate) schema_id: Option<&'static str>,
}

pub const DOCUMENTS: [PinnedDocument; 2] = [
    PinnedDocument {
        path: "docs/adr/ADR-0028-promotion-and-release-authority-v2.md",
        mode: "100644",
        blob_oid: "3b7212501922c71abfa3b3fc4dcf6ae879de87bb",
        content_sha256: "a26a9e3e0abe91fd7dd149aa70e69acc98bf7d88a7a16f1a4ecdfad958b447a9",
        byte_length: 5_974,
        schema_id: None,
    },
    PinnedDocument {
        path: "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md",
        mode: "100644",
        blob_oid: "7dc041799a2187633998a5883cac14221feda73b",
        content_sha256: "281599b27a9c578291527ca6e056de9369073e006687dd1149420d83a2cc86b9",
        byte_length: 26_202,
        schema_id: None,
    },
];
