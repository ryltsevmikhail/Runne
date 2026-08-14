//! Explicit compromise-reset lifecycle.

use gocode_project_owner_authority::{
    ProjectOwnerTrustConfigV1, TrustAnchorState, after_explicit_compromise_declaration,
    key_fingerprint, verify_trust_config,
};
use gocode_secure_store::{
    ProjectOwnerAnchorFloor, ProjectOwnerKeyRef, ProjectOwnerKeyStore, StoreStatus,
};

use super::super::review::AuthorityReviewV1;
use super::{
    AuthorityCommandRunner, AuthorityFiles, AuthorityTty, CommandOutput, TrustResetRequest,
};
use crate::CliError;

impl<S, G, T, R, C, F> AuthorityCommandRunner<'_, S, G, T, R, C, F>
where
    S: ProjectOwnerKeyStore,
    T: AuthorityTty,
    F: AuthorityFiles,
{
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the command runner owns its request boundary"
    )]
    pub(super) fn trust_reset(self, request: TrustResetRequest) -> Result<CommandOutput, CliError> {
        self.files
            .validate_repo_public_output(&request.trust_config)?;
        let active = load_active_trust(self.store, self.files, &request.trust_config)?;
        let reset = after_explicit_compromise_declaration(&active.trust);
        if reset.repository_id != "gocode"
            || reset.compromised_key_id != active.trust.key_id
            || reset.compromised_epoch != active.trust.epoch
        {
            return Err(CliError::AuthorityTrustResetRebootstrapRequired);
        }
        let review = review(&active.trust)?;
        let challenge = review
            .confirmation_challenge()
            .map_err(|_| CliError::AuthorityUnavailable)?;
        if request.acknowledgement != challenge {
            return Err(CliError::AuthorityUnavailable);
        }
        let display = review
            .public_display()
            .map_err(|_| CliError::AuthorityUnavailable)?;
        self.tty.confirm(&display, &challenge)?;
        self.store
            .reset_after_compromise(&active.key, &active.floor)
            .map_err(store_error)?;
        Ok(CommandOutput {
            stdout: b"TRUST_RESET_REQUIRES_NEW_GENESIS_AND_OUT_OF_BAND_REBOOTSTRAP\n".to_vec(),
            artifacts: vec![],
        })
    }
}

struct ActiveTrust {
    trust: ProjectOwnerTrustConfigV1,
    key: ProjectOwnerKeyRef,
    floor: ProjectOwnerAnchorFloor,
}

fn load_active_trust<S: ProjectOwnerKeyStore, F: AuthorityFiles>(
    store: &S,
    files: &F,
    trust_path: &str,
) -> Result<ActiveTrust, CliError> {
    let trust = ProjectOwnerTrustConfigV1::from_json(&files.bounded_nofollow_read(trust_path)?)
        .map_err(|_| CliError::AuthorityUnavailable)?;
    let key = store
        .read_active_ref("gocode")
        .map_err(store_error)?
        .ok_or(CliError::AuthorityUnavailable)?;
    let floor = store
        .read_anchor_floor("gocode")
        .map_err(store_error)?
        .ok_or(CliError::AuthorityUnavailable)?;
    if key.key_epoch() != trust.epoch || key.public_key() != trust.public_key {
        return Err(CliError::AuthorityUnavailable);
    }
    let anchor = TrustAnchorState::confirmed(
        "gocode".into(),
        floor.highest_key_epoch(),
        floor.accepted_trust_config_sha256(),
    );
    verify_trust_config(&trust, &anchor).map_err(|_| CliError::AuthorityUnavailable)?;
    Ok(ActiveTrust { trust, key, floor })
}

fn review(trust: &ProjectOwnerTrustConfigV1) -> Result<AuthorityReviewV1, CliError> {
    Ok(AuthorityReviewV1 {
        schema_version: "gocode.authority.cli-review/1".into(),
        operation: "trust-reset".into(),
        repository_id: "gocode".into(),
        purpose: None,
        profile: None,
        subject: None,
        documents: vec![],
        trust_config_sha256: hex(&trust.sha256().map_err(|_| CliError::AuthorityUnavailable)?),
        key_id: hex(&trust.key_id),
        key_fingerprint: hex(&key_fingerprint(&trust.public_key)),
        key_epoch: trust.epoch,
        issued_at: None,
        signing_transcript_sha256: None,
        output: None,
        rotation: None,
        backup: None,
        continuity: "discontinuity".into(),
    })
}

const fn store_error(_: StoreStatus) -> CliError {
    CliError::AuthorityStoreUnavailable
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(value, "{byte:02x}").expect("writing to String is infallible");
    }
    value
}
