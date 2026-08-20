use super::*;
use sha2::{Digest as _, Sha256};

pub fn decode(
    bytes: &[u8],
    binding: &ThresholdFixtureStoreBinding,
) -> Result<FileState, AuthorityError> {
    let text = std::str::from_utf8(bytes).map_err(|_| AuthorityError::NonCanonicalPayload)?;
    let mut lines = text.lines();
    (lines.next() == Some("gocode.release.durable-threshold-context/1"))
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)?;
    let bootstrap = value(&mut lines, "bootstrap")?;
    let profile = value(&mut lines, "profile")?;
    let version = number(value(&mut lines, "version")?)?;
    (bootstrap == binding.bootstrap.to_hex()
        && profile == binding.profile
        && version == binding.version)
        .then_some(())
        .ok_or(AuthorityError::BindingMismatch)?;
    let now = number(value(&mut lines, "now")?)?;
    let state = read_state(&mut lines, "state")?;
    let count = usize::try_from(number(value(&mut lines, "journal_count")?)?)
        .map_err(|_| AuthorityError::NonCanonicalPayload)?;
    let mut journal = Vec::with_capacity(count);
    for _ in 0..count {
        journal.push(read_journal(&mut lines)?);
    }
    unique_journal_keys(&journal)?;
    let ack_count = usize::try_from(number(value(&mut lines, "ack_count")?)?)
        .map_err(|_| AuthorityError::NonCanonicalPayload)?;
    let mut acknowledgements = Vec::with_capacity(ack_count);
    for _ in 0..ack_count {
        let (admission, revision) = value(&mut lines, "ack")?
            .split_once('@')
            .ok_or(AuthorityError::NonCanonicalPayload)?;
        acknowledgements.push(Acknowledgement {
            admission: digest(admission)?,
            revision: number(revision)?,
        });
    }
    lines
        .next()
        .is_none()
        .then_some(FileState {
            state,
            now,
            journal,
            acknowledgements,
        })
        .ok_or(AuthorityError::NonCanonicalPayload)
}

fn unique_journal_keys(journal: &[JournalEntry]) -> Result<(), AuthorityError> {
    let mut keys = std::collections::BTreeSet::new();
    journal
        .iter()
        .all(|entry| {
            keys.insert((
                entry.scope.authority_instance,
                entry.scope.promotion.as_str(),
                entry.scope.revision,
                entry.scope.command.as_str(),
            ))
        })
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)
}

fn value<'a>(lines: &mut std::str::Lines<'a>, key: &str) -> Result<&'a str, AuthorityError> {
    lines
        .next()
        .and_then(|line| line.strip_prefix(&format!("{key}=")))
        .ok_or(AuthorityError::NonCanonicalPayload)
}
fn read_state(
    lines: &mut std::str::Lines<'_>,
    prefix: &str,
) -> Result<ThresholdVerificationState, AuthorityError> {
    let versions = read_numbers(value(lines, &format!("{prefix}_versions"))?)?;
    let rollback_floor = number(value(lines, &format!("{prefix}_rollback_floor"))?)?;
    let revocation_floor = number(value(lines, &format!("{prefix}_revocation_floor"))?)?;
    let frozen = match value(lines, &format!("{prefix}_frozen"))? {
        "0" => false,
        "1" => true,
        _ => return Err(AuthorityError::NonCanonicalPayload),
    };
    let generation = number(value(lines, &format!("{prefix}_generation"))?)?;
    let root_keys = read_keys(value(lines, &format!("{prefix}_root_keys"))?)?;
    let targets_keys = read_keys(value(lines, &format!("{prefix}_targets_keys"))?)?;
    let snapshot_key = one_key(value(lines, &format!("{prefix}_snapshot_key"))?)?;
    let timestamp_key = one_key(value(lines, &format!("{prefix}_timestamp_key"))?)?;
    let channel_policy_id = match value(lines, &format!("{prefix}_channel_policy_id"))? {
        "" => None,
        policy if canonical_id(policy) => Some(policy.into()),
        _ => return Err(AuthorityError::NonCanonicalPayload),
    };
    let role_bodies = value(lines, &format!("{prefix}_role_bodies"))?
        .split(',')
        .filter(|item| !item.is_empty())
        .map(|item| {
            let (role, body) = item
                .split_once('@')
                .ok_or(AuthorityError::NonCanonicalPayload)?;
            canonical_id(role)
                .then_some((role.into(), unhex(body)?))
                .ok_or(AuthorityError::NonCanonicalPayload)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let role_digests = value(lines, &format!("{prefix}_role_digests"))?
        .split(',')
        .filter(|item| !item.is_empty())
        .map(|item| {
            let (role, raw) = item
                .split_once('@')
                .ok_or(AuthorityError::NonCanonicalPayload)?;
            canonical_id(role)
                .then_some((role.into(), digest(raw)?))
                .ok_or(AuthorityError::NonCanonicalPayload)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    (role_digests.len() == role_bodies.len()
        && role_bodies.iter().all(|(role, body)| {
            role_digests.get(role) == Some(&Digest::from_bytes(Sha256::digest(body).into()))
        }))
    .then_some(())
    .ok_or(AuthorityError::NonCanonicalPayload)?;
    Ok(ThresholdVerificationState {
        versions,
        rollback_floor,
        revocation_floor,
        frozen,
        generation,
        root_keys,
        targets_keys,
        snapshot_key,
        timestamp_key,
        channel_policy_id,
        role_bodies,
        role_digests,
    })
}
fn read_journal(lines: &mut std::str::Lines<'_>) -> Result<JournalEntry, AuthorityError> {
    let parts = value(lines, "journal_scope")?
        .split('@')
        .collect::<Vec<_>>();
    (parts.len() == 10)
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)?;
    let scope = ThresholdAdmissionScope {
        authority_instance: digest(parts[0])?,
        promotion: text(parts[1])?,
        revision: number(parts[2])?,
        command: text(parts[3])?,
        authorization: digest(parts[4])?,
        commitment: digest(parts[5])?,
        candidate: digest(parts[6])?,
        inventory: digest(parts[7])?,
        metadata: digest(parts[8])?,
        report: digest(parts[9])?,
    };
    let admission = digest(value(lines, "journal_admission")?)?;
    let next = read_state(lines, "journal_next")?;
    Ok(JournalEntry {
        scope,
        admission,
        next,
    })
}
fn number(value: &str) -> Result<u64, AuthorityError> {
    value
        .parse()
        .map_err(|_| AuthorityError::NonCanonicalPayload)
}
fn read_numbers(value: &str) -> Result<BTreeMap<String, u64>, AuthorityError> {
    value
        .split(',')
        .filter(|x| !x.is_empty())
        .map(|part| {
            let (k, v) = part
                .split_once('@')
                .ok_or(AuthorityError::NonCanonicalPayload)?;
            canonical_id(k)
                .then_some((k.into(), number(v)?))
                .ok_or(AuthorityError::NonCanonicalPayload)
        })
        .collect()
}
fn read_keys(value: &str) -> Result<BTreeMap<String, [u8; 32]>, AuthorityError> {
    value
        .split(',')
        .filter(|x| !x.is_empty())
        .map(|part| {
            let (k, v) = part
                .split_once('@')
                .ok_or(AuthorityError::NonCanonicalPayload)?;
            canonical_id(k)
                .then_some((k.into(), array(v)?))
                .ok_or(AuthorityError::NonCanonicalPayload)
        })
        .collect()
}
fn one_key(value: &str) -> Result<(String, [u8; 32]), AuthorityError> {
    let (id, key) = value
        .split_once('@')
        .ok_or(AuthorityError::NonCanonicalPayload)?;
    canonical_id(id)
        .then_some((id.into(), array(key)?))
        .ok_or(AuthorityError::NonCanonicalPayload)
}
fn digest(value: &str) -> Result<Digest, AuthorityError> {
    Ok(Digest::from_bytes(array(value)?))
}
fn text(value: &str) -> Result<String, AuthorityError> {
    let bytes = unhex(value)?;
    String::from_utf8(bytes).map_err(|_| AuthorityError::NonCanonicalPayload)
}
fn array(value: &str) -> Result<[u8; 32], AuthorityError> {
    let bytes = unhex(value)?;
    bytes
        .try_into()
        .map_err(|_| AuthorityError::NonCanonicalPayload)
}
pub fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}
fn unhex(value: &str) -> Result<Vec<u8>, AuthorityError> {
    value
        .len()
        .is_multiple_of(2)
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)?;
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| AuthorityError::NonCanonicalPayload)
        })
        .collect()
}
pub fn canonical_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
