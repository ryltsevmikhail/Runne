use runne_application::project_trust::admin::{
    AdminError, ManagedPolicyCommandV1, ReservedManagedPolicyCommandV1,
    managed_policy_request_digest_v1,
};
use runne_application::project_trust::{ManagedEffectDecision, ManagedEffectPolicyV1};
use rusqlite::{Connection, OptionalExtension, params};

use super::identity::AdminIdentity;

pub(super) struct StoredCommand {
    pub(super) key: String,
    pub(super) subject: [u8; 32],
    pub(super) authority: [u8; 16],
    pub(super) lineage: [u8; 16],
    pub(super) project: [u8; 16],
    pub(super) epoch: i64,
    pub(super) revision: i64,
    pub(super) old_digest: [u8; 32],
    pub(super) new_digest: [u8; 32],
    pub(super) request_digest: [u8; 32],
    pub(super) versions: [i64; 3],
    pub(super) rules: [i64; 6],
    pub(super) generation: i64,
    pub(super) launch: [u8; 32],
    pub(super) challenge: [u8; 16],
    pub(super) nonce: [u8; 32],
    pub(super) warning: i64,
    pub(super) issued: i64,
    pub(super) expires: i64,
    pub(super) digest: [u8; 32],
    pub(super) state: i64,
}

pub(super) fn load_command(
    connection: &Connection,
    command_id: &[u8; 16],
) -> Result<Option<StoredCommand>, AdminError> {
    let raw = connection
        .query_row(
            "SELECT idempotency_key, stable_subject_digest, authority_id, lineage_id, project_id,
                project_epoch, expected_revision, old_rules_digest, new_rules_digest,
                managed_version, source_policy_version, local_command_policy_version,
                fs_read, fs_create, fs_write, fs_delete, process_start, network_use,
                admin_generation, launch_binding_digest, challenge_id, challenge_nonce,
                warning_version, issued_at_unix_ms, expires_at_unix_ms,
                request_digest, semantic_digest, state
         FROM managed_policy_admin_commands WHERE command_id=?1",
            [command_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, i64>(17)?,
                    row.get::<_, i64>(18)?,
                    row.get::<_, Vec<u8>>(19)?,
                    row.get::<_, Vec<u8>>(20)?,
                    row.get::<_, Vec<u8>>(21)?,
                    row.get::<_, i64>(22)?,
                    row.get::<_, i64>(23)?,
                    row.get::<_, i64>(24)?,
                    row.get::<_, Vec<u8>>(25)?,
                    row.get::<_, Vec<u8>>(26)?,
                    row.get::<_, i64>(27)?,
                ))
            },
        )
        .optional()
        .map_err(|_| AdminError::Unavailable)?;
    raw.map(|r| {
        Ok(StoredCommand {
            key: r.0,
            subject: fixed(r.1)?,
            authority: fixed(r.2)?,
            lineage: fixed(r.3)?,
            project: fixed(r.4)?,
            epoch: r.5,
            revision: r.6,
            old_digest: fixed(r.7)?,
            new_digest: fixed(r.8)?,
            versions: [r.9, r.10, r.11],
            rules: [r.12, r.13, r.14, r.15, r.16, r.17],
            generation: r.18,
            launch: fixed(r.19)?,
            challenge: fixed(r.20)?,
            nonce: fixed(r.21)?,
            warning: r.22,
            issued: r.23,
            expires: r.24,
            request_digest: fixed(r.25)?,
            digest: fixed(r.26)?,
            state: r.27,
        })
    })
    .transpose()
}

pub(super) fn find_command_id(
    connection: &Connection,
    command: &ManagedPolicyCommandV1,
    identity: &AdminIdentity,
) -> Result<Option<[u8; 16]>, AdminError> {
    let value: Option<Vec<u8>> = connection
        .query_row(
            "SELECT command_id FROM managed_policy_admin_commands
         WHERE command_id=?1 OR (stable_subject_digest=?2 AND idempotency_key=?3) LIMIT 1",
            params![
                command.command_id().as_slice(),
                identity.stable_digest.as_slice(),
                command.idempotency_key()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| AdminError::Unavailable)?;
    value.map(fixed).transpose()
}

pub(super) fn command_matches(
    row: &StoredCommand,
    command: &ReservedManagedPolicyCommandV1,
    identity: &AdminIdentity,
) -> bool {
    let versions = [1, 2, 1];
    let rules = command
        .rules()
        .decisions()
        .map(|value| i64::from(value.code()));
    row.key == command.idempotency_key()
        && row.subject == identity.stable_digest
        && row.authority == identity.authority_id
        && row.lineage == identity.lineage_id
        && row.project == *command.project().as_bytes()
        && u64::try_from(row.epoch).ok() == Some(command.expected().instance_epoch)
        && u64::try_from(row.revision).ok() == Some(command.expected().revision)
        && row.old_digest == *command.old_rules_digest()
        && row.new_digest == *command.new_rules_digest()
        && row.request_digest == *command.request_digest()
        && row.versions == versions
        && row.rules == rules
        && u64::try_from(row.generation).ok() == Some(command.admin_generation())
        && row.launch == *command.launch_binding_digest()
        && row.challenge == *command.challenge_id()
        && row.nonce == *command.challenge_nonce()
        && u16::try_from(row.warning).ok() == Some(command.warning_version())
        && row.issued == command.issued_at_unix_ms()
        && row.expires == command.expires_at_unix_ms()
        && row.digest == *command.semantic_digest()
}

pub(super) fn public_intent_matches(
    row: &StoredCommand,
    request: &ManagedPolicyCommandV1,
    identity: &AdminIdentity,
) -> bool {
    row.key == request.idempotency_key()
        && row.subject == identity.stable_digest
        && row.authority == identity.authority_id
        && row.lineage == identity.lineage_id
        && row.project == *request.project().as_bytes()
        && u64::try_from(row.epoch).ok() == Some(request.expected().instance_epoch)
        && u64::try_from(row.revision).ok() == Some(request.expected().revision)
        && row.old_digest == *request.old_rules_digest()
        && row.new_digest == *request.new_rules_digest()
        && row.request_digest == *request.request_digest()
        && row.request_digest == managed_policy_request_digest_v1(request)
        && row.versions == [1, 2, 1]
        && row.rules
            == request
                .rules()
                .decisions()
                .map(|value| i64::from(value.code()))
        && u16::try_from(row.warning).ok() == Some(request.warning_version())
}

pub(super) fn decode_policy(
    row: (i64, i64, i64, i64, i64, i64, i64),
) -> Option<ManagedEffectPolicyV1> {
    let version = u32::try_from(row.0).ok()?;
    let values = [row.1, row.2, row.3, row.4, row.5, row.6];
    let decisions = values.map(|value| {
        u8::try_from(value)
            .ok()
            .and_then(ManagedEffectDecision::from_code)
    });
    Some(ManagedEffectPolicyV1::new(
        version,
        [
            decisions[0]?,
            decisions[1]?,
            decisions[2]?,
            decisions[3]?,
            decisions[4]?,
            decisions[5]?,
        ],
    ))
    .filter(|policy| policy.is_valid())
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], AdminError> {
    value.try_into().map_err(|_| AdminError::Unavailable)
}
