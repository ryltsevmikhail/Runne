//! Atomic owner-key rotation after explicit review.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use runne_project_owner_authority::{
    KeyRotationV1, ProjectOwnerTrustConfigV1, TrustAnchorState, key_fingerprint, key_id,
    rotation_new_pop_transcript, rotation_old_authorization_transcript, verify_rotation,
    verify_trust_config,
};
use runne_secure_store::{
    PendingProjectOwnerKey, ProjectOwnerAnchorFloor, ProjectOwnerKeyRef, ProjectOwnerKeyStore,
    StoreStatus,
};

use super::super::review::{AuthorityReviewV1, ReviewOutput, ReviewRotation};
use super::output_set::{OutputArtifact, rotation_set, write_and_verify};
use super::{
    ArtifactReceipt, AuthorityCommandRunner, AuthorityFiles, AuthorityGitResolver, AuthorityRng,
    AuthorityTty, CommandOutput, RotateRequest,
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
    pub(super) fn rotate(self, request: RotateRequest) -> Result<CommandOutput, CliError> {
        self.files
            .validate_repo_public_output(&request.trust_config)?;
        self.files
            .validate_repo_public_output(&request.rotation_out)?;
        self.files
            .validate_repo_public_output(&request.successor_trust_out)?;
        let active = load_active_trust(self.store, self.files, &request.trust_config)?;
        let prepared = prepare_rotation(self.store, &active.trust, &active.key)?;
        let rotation_bytes = prepared
            .rotation
            .to_canonical_json()
            .map_err(|_| CliError::AuthorityUnavailable)?;
        let successor_bytes = prepared
            .successor
            .to_canonical_json()
            .map_err(|_| CliError::AuthorityUnavailable)?;
        let outputs = rotation_set(
            OutputArtifact {
                role: "rotation",
                path: &request.rotation_out,
                bytes: &rotation_bytes,
            },
            OutputArtifact {
                role: "successor-trust",
                path: &request.successor_trust_out,
                bytes: &successor_bytes,
            },
        )?;
        let review = review(
            &active.trust,
            &prepared.rotation,
            &outputs,
            &prepared.old_authorization_transcript,
        )?;
        let manifest = String::from_utf8(outputs.manifest.clone())
            .map_err(|_| CliError::AuthorityUnavailable)?;
        let display = format!(
            "{manifest}{}",
            review
                .public_display()
                .map_err(|_| CliError::AuthorityUnavailable)?
        );
        self.tty.confirm(
            &display,
            &review
                .confirmation_challenge()
                .map_err(|_| CliError::AuthorityUnavailable)?,
        )?;
        write_and_verify(
            self.files,
            OutputArtifact {
                role: "rotation",
                path: &request.rotation_out,
                bytes: &rotation_bytes,
            },
            OutputArtifact {
                role: "successor-trust",
                path: &request.successor_trust_out,
                bytes: &successor_bytes,
            },
            &outputs,
        )?;
        let new_floor = ProjectOwnerAnchorFloor::new(
            "runne",
            prepared.successor.epoch,
            prepared
                .successor
                .sha256()
                .map_err(|_| CliError::AuthorityUnavailable)?,
        )
        .map_err(store_error)?;
        if self
            .store
            .commit_pending_and_floor(
                Some(&active.key),
                prepared.pending,
                Some(&active.floor),
                &new_floor,
            )
            .map_err(store_error)?
            != prepared.reference
        {
            return Err(CliError::AuthorityUnavailable);
        }
        Ok(CommandOutput {
            stdout: display.into_bytes(),
            artifacts: vec![
                ArtifactReceipt {
                    kind: "rotation".into(),
                    path: request.rotation_out,
                    sha256: sha256(&rotation_bytes),
                },
                ArtifactReceipt {
                    kind: "successor-trust".into(),
                    path: request.successor_trust_out,
                    sha256: sha256(&successor_bytes),
                },
            ],
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
    let trust = ProjectOwnerTrustConfigV1::from_json(&files.read_repo_public(trust_path)?)
        .map_err(|_| CliError::AuthorityUnavailable)?;
    let key = store
        .read_active_ref("runne")
        .map_err(store_error)?
        .ok_or(CliError::AuthorityUnavailable)?;
    let floor = store
        .read_anchor_floor("runne")
        .map_err(store_error)?
        .ok_or(CliError::AuthorityUnavailable)?;
    let anchor = TrustAnchorState::confirmed(
        "runne".into(),
        floor.highest_key_epoch(),
        floor.accepted_trust_config_sha256(),
    );
    if key.key_epoch() != trust.epoch || key.public_key() != trust.public_key {
        return Err(CliError::AuthorityUnavailable);
    }
    verify_trust_config(&trust, &anchor).map_err(|_| CliError::AuthorityTrustInvalid)?;
    Ok(ActiveTrust { trust, key, floor })
}

struct PreparedRotation {
    pending: PendingProjectOwnerKey,
    reference: ProjectOwnerKeyRef,
    rotation: KeyRotationV1,
    successor: ProjectOwnerTrustConfigV1,
    old_authorization_transcript: Vec<u8>,
}

fn prepare_rotation<S: ProjectOwnerKeyStore>(
    store: &S,
    old: &ProjectOwnerTrustConfigV1,
    active: &ProjectOwnerKeyRef,
) -> Result<PreparedRotation, CliError> {
    let mut pop = |reference: &ProjectOwnerKeyRef| {
        rotation_new_pop_transcript(old, &rotation(old, reference, [0; 64], [0; 64]))
            .map_err(|_| StoreStatus::Denied)
    };
    let pending = store
        .create_or_resume_pending(Some(active), "runne", old.epoch + 1, &mut pop)
        .map_err(store_error)?;
    let reference = pending.key_ref().clone();
    let provisional = rotation(old, &reference, [0; 64], pending.proof_of_possession());
    let old_authorization_transcript = rotation_old_authorization_transcript(&provisional)
        .map_err(|_| CliError::AuthorityUnavailable)?;
    let old_authorization = store
        .sign_active(active, &old_authorization_transcript)
        .map_err(store_error)?;
    let rotation = rotation(
        old,
        &reference,
        old_authorization,
        pending.proof_of_possession(),
    );
    let successor = verify_rotation(old, &rotation).map_err(|_| CliError::AuthorityTrustInvalid)?;
    Ok(PreparedRotation {
        pending,
        reference,
        rotation,
        successor,
        old_authorization_transcript,
    })
}
pub(super) fn review(
    old: &ProjectOwnerTrustConfigV1,
    rotation: &KeyRotationV1,
    outputs: &super::output_set::OutputSet,
    old_authorization_payload: &[u8],
) -> Result<AuthorityReviewV1, CliError> {
    Ok(AuthorityReviewV1 {
        schema_version: "runne.authority.cli-review/1".into(),
        operation: "rotate".into(),
        repository_id: "runne".into(),
        purpose: None,
        profile: None,
        subject: None,
        documents: vec![],
        trust_config_sha256: hex(&old.sha256().map_err(|_| CliError::AuthorityUnavailable)?),
        key_id: hex(&old.key_id),
        key_fingerprint: hex(&key_fingerprint(&old.public_key)),
        key_epoch: old.epoch,
        issued_at: None,
        signing_transcript_sha256: None,
        output: Some(ReviewOutput {
            artifact_sha256: Some(hex(&outputs.digest)),
            byte_length: Some(
                u64::try_from(outputs.manifest.len())
                    .map_err(|_| CliError::AuthorityUnavailable)?,
            ),
            kind: "repository-artifact-set-v1".into(),
            locator: "rotation+successor-trust".into(),
        }),
        rotation: Some(ReviewRotation {
            new_epoch: rotation.new_epoch,
            new_key_fingerprint: hex(&key_fingerprint(&rotation.new_public_key)),
            new_key_id: hex(&rotation.new_key_id),
            new_public_key: URL_SAFE_NO_PAD.encode(rotation.new_public_key),
            old_authorization_payload_sha256: hex(&sha256(old_authorization_payload)),
            old_epoch: rotation.old_epoch,
            old_key_id: hex(&rotation.old_key_id),
            predecessor_config_sha256: hex(&rotation.predecessor_config_sha256),
        }),
        backup: None,
        continuity: "continuous".into(),
    })
}
fn rotation(
    old: &ProjectOwnerTrustConfigV1,
    reference: &ProjectOwnerKeyRef,
    old_authorization: [u8; 64],
    new_proof: [u8; 64],
) -> KeyRotationV1 {
    KeyRotationV1 {
        schema_version: "runne.project-owner.key-rotation/1".into(),
        repository_id: "runne".into(),
        role: "PROJECT_OWNER".into(),
        predecessor_config_sha256: old.sha256().expect("verified"),
        old_key_id: old.key_id,
        old_epoch: old.epoch,
        new_key_id: key_id(&reference.public_key()),
        new_public_key: reference.public_key(),
        new_epoch: reference.key_epoch(),
        old_authorization,
        new_proof_of_possession: new_proof,
    }
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
fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes).into()
}
