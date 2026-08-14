//! Explicitly reviewed same-anchor owner-key recovery.

use gocode_project_owner_authority::{
    AuthorityError, BackupMetadataV1, BackupPassphrase, ProjectOwnerTrustConfigV1,
    TrustAnchorState, decrypt_backup, key_fingerprint, key_id, verify_trust_config,
};
use gocode_secure_store::{
    ProjectOwnerAnchorFloor, ProjectOwnerKeyMaterial, ProjectOwnerKeyRef, ProjectOwnerKeyStore,
    StoreStatus,
};
use sha2::{Digest as _, Sha256};

use super::super::review::{AuthorityReviewV1, ReviewBackup, ReviewOutput};
use super::{
    ArtifactReceipt, AuthorityCommandRunner, AuthorityFiles, AuthorityGitResolver, AuthorityRng,
    AuthorityTty, CommandOutput, RestoreRequest,
};
use crate::CliError;

const MAX_PASSPHRASE_BYTES: usize = 4096;

impl<S, G, T, R, C, F> AuthorityCommandRunner<'_, S, G, T, R, C, F>
where
    S: ProjectOwnerKeyStore,
    G: AuthorityGitResolver,
    T: AuthorityTty,
    R: AuthorityRng,
    C: super::AuthorityClock,
    F: AuthorityFiles,
{
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the command runner owns its request boundary"
    )]
    pub(super) fn restore(self, request: RestoreRequest) -> Result<CommandOutput, CliError> {
        self.files
            .validate_repo_public_output(&request.trust_config)?;
        let locator = self
            .files
            .validate_external_path(&request.input, self.git.repository_root())?;
        if request.replace_active_trust.is_some() != request.replace_active_key_id.is_some() {
            return Err(CliError::AuthorityUsage);
        }
        let backup_bytes = self.files.bounded_nofollow_read(&request.input)?;
        let metadata = BackupMetadataV1::from_json(&backup_bytes)
            .map_err(|_| CliError::AuthorityUnavailable)?;
        let (trust, floor) = anchored_trust(self.store, self.files, &request.trust_config)?;
        let current = expected_current(
            self.store,
            self.files,
            &trust,
            &floor,
            request.replace_active_trust.as_deref(),
            request.replace_active_key_id,
        )?;
        let passphrase = self.tty.read_hidden("Backup passphrase")?;
        if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE_BYTES {
            return Err(CliError::AuthorityUnavailable);
        }
        let seed = decrypt_backup(&metadata, BackupPassphrase::new(passphrase), &trust)
            .map_err(|error| backup_error(&error))?;
        let target = ProjectOwnerKeyRef::new("gocode", trust.public_key, trust.epoch)
            .map_err(store_error)?;
        let material =
            ProjectOwnerKeyMaterial::from_backup_seed(target.clone(), seed).map_err(store_error)?;
        let digest = sha256(&backup_bytes);
        let review = review(&trust, &metadata, digest, backup_bytes.len(), &locator)?;
        let display = review
            .public_display()
            .map_err(|_| CliError::AuthorityUnavailable)?;
        self.tty.confirm(
            &display,
            &review
                .confirmation_challenge()
                .map_err(|_| CliError::AuthorityUnavailable)?,
        )?;
        if self
            .store
            .restore_active(current.as_ref(), material)
            .map_err(store_error)?
            != target
            || self
                .store
                .read_anchor_floor("gocode")
                .map_err(store_error)?
                != Some(floor)
        {
            return Err(CliError::AuthorityUnavailable);
        }
        Ok(CommandOutput {
            stdout: display.into_bytes(),
            artifacts: vec![ArtifactReceipt {
                kind: "encrypted-key-backup-input".into(),
                path: locator,
                sha256: digest,
            }],
        })
    }
}

fn anchored_trust<S: ProjectOwnerKeyStore, F: AuthorityFiles>(
    store: &S,
    files: &F,
    path: &str,
) -> Result<(ProjectOwnerTrustConfigV1, ProjectOwnerAnchorFloor), CliError> {
    let trust = ProjectOwnerTrustConfigV1::from_json(&files.bounded_nofollow_read(path)?)
        .map_err(|_| CliError::AuthorityUnavailable)?;
    let floor = store
        .read_anchor_floor("gocode")
        .map_err(store_error)?
        .ok_or(CliError::AuthorityUnavailable)?;
    let anchor = TrustAnchorState::confirmed(
        "gocode".into(),
        floor.highest_key_epoch(),
        floor.accepted_trust_config_sha256(),
    );
    verify_trust_config(&trust, &anchor).map_err(|_| CliError::AuthorityUnavailable)?;
    Ok((trust, floor))
}

fn expected_current<S: ProjectOwnerKeyStore, F: AuthorityFiles>(
    store: &S,
    files: &F,
    target: &ProjectOwnerTrustConfigV1,
    floor: &ProjectOwnerAnchorFloor,
    replacement_path: Option<&str>,
    replacement_key_id: Option<[u8; 32]>,
) -> Result<Option<ProjectOwnerKeyRef>, CliError> {
    let current = store.read_active_ref("gocode").map_err(store_error)?;
    let (Some(path), Some(supplied_key_id), Some(reference)) =
        (replacement_path, replacement_key_id, current.as_ref())
    else {
        return if replacement_path.is_none() && replacement_key_id.is_none() && current.is_none() {
            Ok(None)
        } else {
            Err(CliError::AuthorityUnavailable)
        };
    };
    files.validate_repo_public_output(path)?;
    let current_trust = ProjectOwnerTrustConfigV1::from_json(&files.bounded_nofollow_read(path)?)
        .map_err(|_| CliError::AuthorityUnavailable)?;
    let anchor = TrustAnchorState::confirmed(
        "gocode".into(),
        floor.highest_key_epoch(),
        floor.accepted_trust_config_sha256(),
    );
    if supplied_key_id != key_id(&reference.public_key())
        || current_trust != *target
        || reference.key_epoch() != current_trust.epoch
        || reference.public_key() != current_trust.public_key
    {
        return Err(CliError::AuthorityUnavailable);
    }
    verify_trust_config(&current_trust, &anchor).map_err(|_| CliError::AuthorityUnavailable)?;
    Ok(current)
}

fn review(
    trust: &ProjectOwnerTrustConfigV1,
    metadata: &BackupMetadataV1,
    digest: [u8; 32],
    byte_length: usize,
    locator: &str,
) -> Result<AuthorityReviewV1, CliError> {
    let parameters = metadata.parameters();
    Ok(AuthorityReviewV1 {
        schema_version: "gocode.authority.cli-review/1".into(),
        operation: "restore".into(),
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
        continuity: "restore-same-anchor".into(),
    })
}

fn backup_error(error: &AuthorityError) -> CliError {
    if *error == AuthorityError::BackupTamperedOrWrongPassphrase {
        CliError::AuthorityBackupTamperedOrWrongPassphrase
    } else {
        CliError::AuthorityUnavailable
    }
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
