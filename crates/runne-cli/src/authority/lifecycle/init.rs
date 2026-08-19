//! Genesis initialization transaction.

use runne_project_owner_authority::{
    ProjectOwnerTrustConfigV1, genesis_pop_transcript, key_fingerprint, key_id,
    v1_platform_scope_schema_digests, verify_genesis,
};
use runne_secure_store::{
    ProjectOwnerAnchorFloor, ProjectOwnerKeyRef, ProjectOwnerKeyStore, StoreStatus,
};
use sha2::{Digest as _, Sha256};

use super::super::review::{AuthorityReviewV1, ReviewOutput};
use super::{
    ArtifactReceipt, AuthorityCommandRunner, AuthorityFiles, AuthorityGitResolver, AuthorityRng,
    AuthorityTty, CommandOutput, InitRequest,
};
use crate::CliError;

impl<S, G, T, R, C, F> AuthorityCommandRunner<'_, S, G, T, R, C, F>
where
    S: ProjectOwnerKeyStore,
    G: AuthorityGitResolver,
    T: AuthorityTty,
    R: AuthorityRng,
    C: super::AuthorityClock,
    F: AuthorityFiles,
{
    pub(super) fn init(self, request: InitRequest) -> Result<CommandOutput, CliError> {
        self.files.validate_repo_public_output(&request.trust_out)?;
        if self
            .store
            .read_active_ref("runne")
            .map_err(store_error)?
            .is_some()
            || self
                .store
                .read_anchor_floor("runne")
                .map_err(store_error)?
                .is_some()
        {
            return Err(CliError::AuthorityArtifactExists);
        }
        let mut pop = |reference: &ProjectOwnerKeyRef| {
            genesis_pop_transcript(&config(reference, [0; 64])).map_err(|_| StoreStatus::Denied)
        };
        let pending = self
            .store
            .create_or_resume_pending(None, "runne", 1, &mut pop)
            .map_err(store_error)?;
        let reference = pending.key_ref().clone();
        let trust = config(&reference, pending.proof_of_possession());
        verify_genesis(&trust).map_err(|_| CliError::AuthorityTrustInvalid)?;
        let bytes = trust
            .to_canonical_json()
            .map_err(|_| CliError::AuthorityUnavailable)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let review = review(&trust, &request.trust_out, digest, bytes.len() as u64)?;
        self.tty.confirm(
            &review
                .public_display()
                .map_err(|_| CliError::AuthorityUnavailable)?,
            &review
                .confirmation_challenge()
                .map_err(|_| CliError::AuthorityUnavailable)?,
        )?;
        self.files
            .create_new_or_exact_repo_public(&request.trust_out, &bytes)?;
        let floor = ProjectOwnerAnchorFloor::new("runne", 1, digest).map_err(store_error)?;
        if self
            .store
            .commit_pending_and_floor(None, pending, None, &floor)
            .map_err(store_error)?
            != reference
        {
            return Err(CliError::AuthorityStoreUnavailable);
        }
        Ok(CommandOutput {
            stdout: review
                .public_display()
                .map_err(|_| CliError::AuthorityUnavailable)?
                .into_bytes(),
            artifacts: vec![ArtifactReceipt {
                kind: "trust-config".into(),
                path: request.trust_out,
                sha256: digest,
            }],
        })
    }
}

fn config(
    reference: &ProjectOwnerKeyRef,
    proof_of_possession: [u8; 64],
) -> ProjectOwnerTrustConfigV1 {
    ProjectOwnerTrustConfigV1 {
        schema_version: "runne.project-owner.trust-config/1".into(),
        repository_id: "runne".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 1,
        key_id: key_id(&reference.public_key()),
        public_key: reference.public_key(),
        schema_digests: v1_platform_scope_schema_digests(),
        proof_of_possession,
        predecessor: None,
    }
}
fn review(
    trust: &ProjectOwnerTrustConfigV1,
    path: &str,
    digest: [u8; 32],
    length: u64,
) -> Result<AuthorityReviewV1, CliError> {
    Ok(AuthorityReviewV1 {
        schema_version: "runne.authority.cli-review/1".into(),
        operation: "init".into(),
        repository_id: "runne".into(),
        purpose: None,
        profile: None,
        subject: None,
        documents: vec![],
        trust_config_sha256: hex(&trust.sha256().map_err(|_| CliError::AuthorityUnavailable)?),
        key_id: hex(&trust.key_id),
        key_fingerprint: hex(&key_fingerprint(&trust.public_key)),
        key_epoch: 1,
        issued_at: None,
        signing_transcript_sha256: None,
        output: Some(ReviewOutput {
            artifact_sha256: Some(hex(&digest)),
            byte_length: Some(length),
            kind: "repository-relative".into(),
            locator: path.into(),
        }),
        rotation: None,
        backup: None,
        continuity: "genesis".into(),
    })
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
