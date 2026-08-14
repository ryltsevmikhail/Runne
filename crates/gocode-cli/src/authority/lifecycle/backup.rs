//! Explicitly reviewed encrypted owner-key backup.

use gocode_project_owner_authority::{
    BackupParameters, BackupPassphrase, BackupRng, ProjectOwnerTrustConfigV1, TrustAnchorState,
    encrypt_backup, key_fingerprint, verify_trust_config,
};
use gocode_secure_store::{ProjectOwnerKeyStore, StoreStatus};
use sha2::{Digest as _, Sha256};

use super::super::review::{AuthorityReviewV1, ReviewBackup, ReviewOutput};
use super::{
    ArtifactReceipt, AuthorityCommandRunner, AuthorityFiles, AuthorityGitResolver, AuthorityRng,
    AuthorityTty, BackupRequest, CommandOutput,
};
use crate::CliError;

const MAX_PASSPHRASE_BYTES: usize = 4096;

impl<S, G, T, R, C, F> AuthorityCommandRunner<'_, S, G, T, R, C, F>
where
    S: ProjectOwnerKeyStore,
    G: AuthorityGitResolver,
    T: AuthorityTty,
    R: AuthorityRng + BackupRng,
    C: super::AuthorityClock,
    F: AuthorityFiles,
{
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the command runner owns its request boundary"
    )]
    pub(super) fn backup(self, request: BackupRequest) -> Result<CommandOutput, CliError> {
        self.files
            .validate_repo_public_output(&request.trust_config)?;
        let locator = self
            .files
            .validate_external_path(&request.output, self.git.repository_root())?;
        let (trust, active) = active_trust(self.store, self.files, &request.trust_config)?;
        let first = passphrase(self.tty.read_hidden("Backup passphrase")?)?;
        let second = passphrase(self.tty.read_hidden("Repeat backup passphrase")?)?;
        if first.as_slice() != second.as_slice() {
            return Err(CliError::AuthorityUnavailable);
        }
        let material = self
            .store
            .export_active_for_backup(&active)
            .map_err(store_error)?;
        let metadata = encrypt_backup(
            material.into_backup_seed(),
            BackupPassphrase::new(first),
            &trust,
            BackupParameters::default(),
            self.rng,
        )
        .map_err(|_| CliError::AuthorityUnavailable)?;
        let bytes = metadata
            .to_canonical_json()
            .map_err(|_| CliError::AuthorityUnavailable)?;
        let digest = sha256(&bytes);
        let review = review(&trust, &metadata, digest, bytes.len(), &locator)?;
        let display = review
            .public_display()
            .map_err(|_| CliError::AuthorityUnavailable)?;
        self.tty.confirm(
            &display,
            &review
                .confirmation_challenge()
                .map_err(|_| CliError::AuthorityUnavailable)?,
        )?;
        self.files
            .create_new_external_0600(&request.output, &bytes)?;
        Ok(CommandOutput {
            stdout: display.into_bytes(),
            artifacts: vec![ArtifactReceipt {
                kind: "encrypted-key-backup".into(),
                path: locator,
                sha256: digest,
            }],
        })
    }
}

fn active_trust<S: ProjectOwnerKeyStore, F: AuthorityFiles>(
    store: &S,
    files: &F,
    path: &str,
) -> Result<
    (
        ProjectOwnerTrustConfigV1,
        gocode_secure_store::ProjectOwnerKeyRef,
    ),
    CliError,
> {
    let trust = ProjectOwnerTrustConfigV1::from_json(&files.bounded_nofollow_read(path)?)
        .map_err(|_| CliError::AuthorityUnavailable)?;
    let active = store
        .read_active_ref("gocode")
        .map_err(store_error)?
        .ok_or(CliError::AuthorityUnavailable)?;
    let floor = store
        .read_anchor_floor("gocode")
        .map_err(store_error)?
        .ok_or(CliError::AuthorityUnavailable)?;
    let anchor = TrustAnchorState::confirmed(
        "gocode".into(),
        floor.highest_key_epoch(),
        floor.accepted_trust_config_sha256(),
    );
    if active.key_epoch() != trust.epoch || active.public_key() != trust.public_key {
        return Err(CliError::AuthorityUnavailable);
    }
    verify_trust_config(&trust, &anchor).map_err(|_| CliError::AuthorityUnavailable)?;
    Ok((trust, active))
}

fn passphrase(value: zeroize::Zeroizing<Vec<u8>>) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
    if value.is_empty() || value.len() > MAX_PASSPHRASE_BYTES {
        Err(CliError::AuthorityUnavailable)
    } else {
        Ok(value)
    }
}

fn review(
    trust: &ProjectOwnerTrustConfigV1,
    metadata: &gocode_project_owner_authority::BackupMetadataV1,
    digest: [u8; 32],
    byte_length: usize,
    locator: &str,
) -> Result<AuthorityReviewV1, CliError> {
    let parameters = metadata.parameters();
    Ok(AuthorityReviewV1 {
        schema_version: "gocode.authority.cli-review/1".into(),
        operation: "backup".into(),
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
        output: Some(ReviewOutput {
            artifact_sha256: Some(hex(&digest)),
            byte_length: Some(
                u64::try_from(byte_length).map_err(|_| CliError::AuthorityUnavailable)?,
            ),
            kind: "external-path-sha256".into(),
            locator: locator.into(),
        }),
        rotation: None,
        backup: Some(ReviewBackup {
            kdf_algorithm: "argon2id".into(),
            iterations: parameters.iterations,
            memory_kib: parameters.memory_kib,
            parallelism: parameters.parallelism,
            backup_bytes_sha256: hex(&digest),
        }),
        continuity: "continuous".into(),
    })
}

const fn store_error(_: StoreStatus) -> CliError {
    CliError::AuthorityStoreUnavailable
}
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(value, "{byte:02x}").expect("writing to String is infallible");
    }
    value
}
