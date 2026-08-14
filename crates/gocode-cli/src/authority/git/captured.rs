//! Private retained immutable subject bytes, unavailable to CLI callers.

use gocode_project_owner_authority::{Document, DocumentBinding, GitSubject, UnsignedReceipt};
use sha2::{Digest as _, Sha256};

pub(in super::super) struct CapturedSubject {
    pub(super) subject: GitSubject,
    pub(super) bindings: Vec<DocumentBinding>,
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(
            dead_code,
            reason = "retained bytes are required only by macOS mutation paths"
        )
    )]
    pub(super) retained_documents: Vec<RetainedDocument>,
}

pub(in super::super) struct RetainedDocument {
    pub(super) binding: DocumentBinding,
    pub(super) bytes: Vec<u8>,
    pub(super) sha256: [u8; 32],
}

impl CapturedSubject {
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(
            dead_code,
            reason = "construction is used by the macOS mutation resolver"
        )
    )]
    pub(in super::super) fn from_documents(
        subject: GitSubject,
        documents: Vec<(DocumentBinding, Vec<u8>)>,
    ) -> Self {
        let bindings = documents
            .iter()
            .map(|(binding, _)| binding.clone())
            .collect();
        let retained_documents = documents
            .into_iter()
            .map(|(binding, bytes)| RetainedDocument {
                sha256: Sha256::digest(&bytes).into(),
                binding,
                bytes,
            })
            .collect();
        Self {
            subject,
            bindings,
            retained_documents,
        }
    }

    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(dead_code, reason = "used by the macOS mutation resolver")
    )]
    pub(in super::super) const fn subject(&self) -> &GitSubject {
        &self.subject
    }
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(dead_code, reason = "used by the macOS mutation resolver")
    )]
    pub(in super::super) fn bindings(&self) -> impl ExactSizeIterator<Item = &DocumentBinding> {
        self.bindings.iter()
    }
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(dead_code, reason = "used by the macOS mutation resolver")
    )]
    pub(in super::super) fn documents(&self) -> impl ExactSizeIterator<Item = &RetainedDocument> {
        self.retained_documents.iter()
    }
    pub(in super::super) fn receipt_input(&self) -> (GitSubject, Vec<DocumentBinding>) {
        (self.subject.clone(), self.bindings.clone())
    }
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(dead_code, reason = "receipt creation is macOS-only")
    )]
    pub(in super::super) fn assert_receipt_binding(
        &self,
        receipt: &UnsignedReceipt,
    ) -> Result<(), super::CliError> {
        let documents = self
            .bindings
            .iter()
            .map(|b| Document {
                path: b.path.clone(),
                mode: b.mode.clone(),
                blob_oid: b.blob_oid.clone(),
                content_sha256: b.content_sha256.clone(),
                byte_length: b.byte_length,
                schema_id: b.schema_id.clone(),
            })
            .collect::<Vec<_>>();
        if receipt.subject != self.subject || receipt.documents != documents {
            return Err(super::CliError::AuthorityGit);
        }
        if self
            .bindings
            .iter()
            .zip(&self.retained_documents)
            .all(|(b, d)| {
                d.binding == *b
                    && Sha256::digest(&d.bytes).as_slice() == d.sha256
                    && b.content_sha256 == hex(&d.sha256)
                    && b.byte_length == d.bytes.len() as u64
            })
        {
            Ok(())
        } else {
            Err(super::CliError::AuthorityGit)
        }
    }
    #[cfg_attr(
        any(test, not(target_os = "macos")),
        expect(
            dead_code,
            reason = "transport digest is asserted only by focused capture tests"
        )
    )]
    #[cfg(any(test, target_os = "macos"))]
    pub fn transport_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(self.subject.commit_oid.as_bytes());
        for (binding, retained) in self.bindings.iter().zip(&self.retained_documents) {
            digest.update(binding.path.as_bytes());
            digest.update(retained.binding.path.as_bytes());
            digest.update(retained.sha256);
            digest.update(&retained.bytes);
        }
        digest.finalize().into()
    }
}

impl RetainedDocument {
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(dead_code, reason = "receipt creation is macOS-only")
    )]
    pub(in super::super) const fn binding(&self) -> &DocumentBinding {
        &self.binding
    }
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(dead_code, reason = "receipt creation is macOS-only")
    )]
    pub(in super::super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[cfg_attr(
    not(any(test, target_os = "macos")),
    expect(dead_code, reason = "receipt creation is macOS-only")
)]
fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_binding_recomputes_retained_document_hashes() {
        let bytes = b"document".to_vec();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let binding = DocumentBinding {
            path: "docs/x".into(),
            mode: "100644".into(),
            blob_oid: "a".repeat(40),
            content_sha256: hex(&digest),
            byte_length: 8,
            schema_id: None,
        };
        let captured = CapturedSubject {
            subject: GitSubject {
                object_format: "sha1".into(),
                commit_oid: "b".repeat(40),
                tree_oid: "c".repeat(40),
            },
            bindings: vec![binding.clone()],
            retained_documents: vec![RetainedDocument {
                binding: binding.clone(),
                bytes,
                sha256: digest,
            }],
        };
        let receipt = UnsignedReceipt {
            schema_version: "x".into(),
            repository_id: "gocode".into(),
            role: "x".into(),
            purpose: "x".into(),
            trust_config_sha256: "x".into(),
            key_id: "x".into(),
            key_epoch: 1,
            subject: captured.subject.clone(),
            documents: vec![Document {
                path: binding.path.clone(),
                mode: binding.mode.clone(),
                blob_oid: binding.blob_oid.clone(),
                content_sha256: binding.content_sha256.clone(),
                byte_length: binding.byte_length,
                schema_id: None,
            }],
            issued_at: "2026-01-01T00:00:00Z".into(),
            profile: "x".into(),
        };
        assert!(captured.assert_receipt_binding(&receipt).is_ok());
        assert_eq!(
            captured.documents().next().expect("document").bytes(),
            b"document"
        );
        assert_eq!(
            captured
                .documents()
                .next()
                .expect("document")
                .binding()
                .byte_length,
            8
        );
        assert_eq!(captured.subject().commit_oid, "b".repeat(40));
        assert_eq!(captured.bindings().len(), 1);
        let (_, input) = captured.receipt_input();
        assert_eq!(input, vec![binding]);
    }
}
