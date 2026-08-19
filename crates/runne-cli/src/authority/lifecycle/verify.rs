//! Explicit-anchor public receipt verification.

use runne_project_owner_authority::{
    ProjectOwnerTrustConfigV1, PurposeProfileV1, TrustAnchorState, inspect_receipt_bytes,
    verify_receipt_bytes_against_subject,
};

use super::{
    AuthorityCommandRunner, AuthorityFiles, AuthorityGitResolver, AuthorityRng, AuthorityTty,
    CommandOutput, VerifyRequest,
};
use crate::CliError;

impl<S, G, T, R, C, F> AuthorityCommandRunner<'_, S, G, T, R, C, F>
where
    G: AuthorityGitResolver,
    T: AuthorityTty,
    R: AuthorityRng,
    C: super::AuthorityClock,
    F: AuthorityFiles,
{
    pub(in super::super) fn verify(
        self,
        request: &VerifyRequest,
    ) -> Result<CommandOutput, CliError> {
        self.files
            .validate_repo_public_output(&request.trust_config)?;
        self.files.validate_repo_public_output(&request.receipt)?;
        let trust = ProjectOwnerTrustConfigV1::from_json(
            &self.files.read_repo_public(&request.trust_config)?,
        )
        .map_err(|_| CliError::AuthorityTrustInvalid)?;
        let receipt = self.files.read_repo_public(&request.receipt)?;
        let inspected =
            inspect_receipt_bytes(&receipt).map_err(|_| CliError::AuthorityVerifyFailed)?;
        let profile = PurposeProfileV1::v1_platform_scope();
        let captured = self.git.resolve_subject(inspected.subject(), &profile)?;
        let (subject, bindings) = captured.receipt_input();
        if subject != *inspected.subject() || bindings.as_slice() != inspected.documents() {
            return Err(CliError::AuthorityVerifyFailed);
        }
        let anchor = TrustAnchorState::confirmed(
            "runne".into(),
            request.anchor_epoch,
            request.anchor_trust_sha256,
        );
        runne_project_owner_authority::verify_trust_config(&trust, &anchor)
            .map_err(|_| CliError::AuthorityAnchorMismatch)?;
        verify_receipt_bytes_against_subject(
            &receipt,
            inspected.checked_in_sha256(),
            &profile,
            &trust,
            &anchor,
            &subject,
            &bindings,
        )
        .map_err(|_| CliError::AuthorityVerifyFailed)?;
        Ok(CommandOutput {
            stdout: b"AUTHORITY_RECEIPT_VERIFIED".to_vec(),
            #[cfg(any(test, target_os = "macos"))]
            artifacts: vec![],
        })
    }
}
