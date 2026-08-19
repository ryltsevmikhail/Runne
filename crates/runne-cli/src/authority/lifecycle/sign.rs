//! Receipt signing with a reviewed immutable Git subject.

use runne_project_owner_authority::{
    AuthorityError, Document, ProjectOwnerSignature, ProjectOwnerTrustConfigV1, PurposeProfileV1,
    Signer, SigningDomain, TrustAnchorState, UnsignedReceipt, canonical_checked_in_receipt,
    canonical_unsigned_receipt, key_fingerprint, sign_receipt, signing_transcript,
    verify_receipt_bytes_against_subject, verify_trust_config,
};
use runne_secure_store::{ProjectOwnerKeyRef, ProjectOwnerKeyStore, StoreStatus};
use sha2::{Digest as _, Sha256};

use super::super::review::{AuthorityReviewV1, ReviewDocument, ReviewOutput, ReviewSubject};
use super::{
    ArtifactReceipt, AuthorityClock, AuthorityCommandRunner, AuthorityFiles, AuthorityGitResolver,
    AuthorityRng, AuthorityTty, CommandOutput, SignRequest,
};
use crate::CliError;

impl<S, G, T, R, C, F> AuthorityCommandRunner<'_, S, G, T, R, C, F>
where
    S: ProjectOwnerKeyStore,
    G: AuthorityGitResolver,
    T: AuthorityTty,
    R: AuthorityRng,
    C: AuthorityClock,
    F: AuthorityFiles,
{
    #[expect(
        clippy::too_many_lines,
        reason = "review confirmation intentionally remains adjacent to signing"
    )]
    pub(super) fn sign(self, request: SignRequest) -> Result<CommandOutput, CliError> {
        if !receipt_path(&request.receipt_out) {
            return Err(CliError::AuthorityUsage);
        }
        self.files
            .validate_repo_public_output(&request.trust_config)?;
        self.files
            .validate_repo_public_output(&request.receipt_out)?;
        let trust = ProjectOwnerTrustConfigV1::from_json(
            &self.files.read_repo_public(&request.trust_config)?,
        )
        .map_err(|_| CliError::AuthorityUnavailable)?;
        let active = self
            .store
            .read_active_ref("runne")
            .map_err(store_error)?
            .ok_or(CliError::AuthorityUnavailable)?;
        let floor = self
            .store
            .read_anchor_floor("runne")
            .map_err(store_error)?
            .ok_or(CliError::AuthorityUnavailable)?;
        let anchor = TrustAnchorState::confirmed(
            "runne".into(),
            floor.highest_key_epoch(),
            floor.accepted_trust_config_sha256(),
        );
        if active.key_epoch() != trust.epoch || active.public_key() != trust.public_key {
            return Err(CliError::AuthorityUnavailable);
        }
        verify_trust_config(&trust, &anchor).map_err(|_| CliError::AuthorityUnavailable)?;
        let profile = PurposeProfileV1::v1_platform_scope();
        let captured = self.git.capture_current(&profile)?;
        let (subject, bindings) = captured.receipt_input();
        let issued_at = self.clock.utc_rfc3339_seconds()?;
        let unsigned = unsigned(&trust, subject, &bindings, issued_at.clone());
        let canonical =
            canonical_unsigned_receipt(&unsigned).map_err(|_| CliError::AuthorityUnavailable)?;
        let domain = SigningDomain::new(
            "runne.project-owner.authority-receipt/1",
            &profile.purpose,
            "runne",
        )
        .map_err(|_| CliError::AuthorityUnavailable)?;
        let transcript: [u8; 32] = Sha256::digest(signing_transcript(&domain, &canonical)).into();
        let review = review(
            &trust,
            &unsigned,
            &bindings,
            &request.receipt_out,
            transcript,
        )?;
        self.tty.confirm(
            &review
                .public_display()
                .map_err(|_| CliError::AuthorityUnavailable)?,
            &review
                .confirmation_challenge()
                .map_err(|_| CliError::AuthorityUnavailable)?,
        )?;
        let receipt_signer = StoreSigner {
            store: self.store,
            reference: &active,
        };
        let signed_receipt = sign_receipt(
            &profile,
            &trust,
            &anchor,
            unsigned.subject.clone(),
            bindings.clone(),
            issued_at,
            &receipt_signer,
        )
        .map_err(|_| CliError::AuthorityUnavailable)?;
        if signed_receipt.unsigned != unsigned {
            return Err(CliError::AuthorityUnavailable);
        }
        let bytes =
            canonical_checked_in_receipt(&signed_receipt.unsigned, &signed_receipt.signature)
                .map_err(|_| CliError::AuthorityUnavailable)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        captured.assert_receipt_binding(&signed_receipt.unsigned)?;
        verify_receipt_bytes_against_subject(
            &bytes,
            digest,
            &profile,
            &trust,
            &anchor,
            &unsigned.subject,
            &bindings,
        )
        .map_err(|_| CliError::AuthorityUnavailable)?;
        self.files
            .create_new_repo_public(&request.receipt_out, &bytes)?;
        Ok(CommandOutput {
            stdout: review
                .public_display()
                .map_err(|_| CliError::AuthorityUnavailable)?
                .into_bytes(),
            artifacts: vec![ArtifactReceipt {
                kind: "receipt".into(),
                path: request.receipt_out,
                sha256: digest,
            }],
        })
    }
}

struct StoreSigner<'a, S> {
    store: &'a S,
    reference: &'a ProjectOwnerKeyRef,
}
impl<S: ProjectOwnerKeyStore> Signer for StoreSigner<'_, S> {
    fn sign(&self, transcript: &[u8]) -> Result<ProjectOwnerSignature, AuthorityError> {
        self.store
            .sign_active(self.reference, transcript)
            .map_err(|_| AuthorityError::InvalidReceiptSignature)
    }
}
fn unsigned(
    trust: &ProjectOwnerTrustConfigV1,
    subject: runne_project_owner_authority::GitSubject,
    bindings: &[runne_project_owner_authority::DocumentBinding],
    issued_at: String,
) -> UnsignedReceipt {
    UnsignedReceipt {
        schema_version: "runne.project-owner.authority-receipt/1".into(),
        repository_id: "runne".into(),
        role: "PROJECT_OWNER".into(),
        purpose: "V1_PLATFORM_SCOPE_AUTHORIZATION".into(),
        trust_config_sha256: hex(&trust.sha256().expect("validated")),
        key_id: hex(&trust.key_id),
        key_epoch: trust.epoch,
        subject,
        documents: bindings
            .iter()
            .map(|x| Document {
                path: x.path.clone(),
                mode: x.mode.clone(),
                blob_oid: x.blob_oid.clone(),
                content_sha256: x.content_sha256.clone(),
                byte_length: x.byte_length,
                schema_id: x.schema_id.clone(),
            })
            .collect(),
        issued_at,
        profile: "runne.project-owner.v1-platform-scope/1".into(),
    }
}
fn review(
    trust: &ProjectOwnerTrustConfigV1,
    unsigned: &UnsignedReceipt,
    bindings: &[runne_project_owner_authority::DocumentBinding],
    output: &str,
    transcript: [u8; 32],
) -> Result<AuthorityReviewV1, CliError> {
    Ok(AuthorityReviewV1 {
        schema_version: "runne.authority.cli-review/1".into(),
        operation: "sign".into(),
        repository_id: "runne".into(),
        purpose: Some(unsigned.purpose.clone()),
        profile: Some(unsigned.profile.clone()),
        subject: Some(ReviewSubject {
            commit_oid: unsigned.subject.commit_oid.clone(),
            object_format: unsigned.subject.object_format.clone(),
            tree_oid: unsigned.subject.tree_oid.clone(),
        }),
        documents: bindings
            .iter()
            .map(|x| ReviewDocument {
                blob_oid: x.blob_oid.clone(),
                byte_length: x.byte_length,
                content_sha256: x.content_sha256.clone(),
                mode: x.mode.clone(),
                path: x.path.clone(),
                schema_id: x.schema_id.clone(),
            })
            .collect(),
        trust_config_sha256: hex(&trust.sha256().map_err(|_| CliError::AuthorityUnavailable)?),
        key_id: hex(&trust.key_id),
        key_fingerprint: hex(&key_fingerprint(&trust.public_key)),
        key_epoch: trust.epoch,
        issued_at: Some(unsigned.issued_at.clone()),
        signing_transcript_sha256: Some(hex(&transcript)),
        output: Some(ReviewOutput {
            artifact_sha256: None,
            byte_length: None,
            kind: "repository-relative".into(),
            locator: output.into(),
        }),
        rotation: None,
        backup: None,
        continuity: "continuous".into(),
    })
}
fn receipt_path(path: &str) -> bool {
    path.starts_with("docs/evidence/")
        && std::path::Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
}
const fn store_error(_: StoreStatus) -> CliError {
    CliError::AuthorityStoreUnavailable
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}
