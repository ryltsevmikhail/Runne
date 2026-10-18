use super::model::PermissionModeStoreError;
use runne_application::permission_modes::{
    CompositeScopeDigest, ContainmentStrategy, EffectiveModeHistoryState, NetworkState,
    NotReadyReason, PermissionMode, PermissionModeHistoryProjection, PresetVersion,
};

const VERSION: u8 = 1;

pub(super) fn encode_history(
    value: &PermissionModeHistoryProjection,
) -> Result<Vec<u8>, PermissionModeStoreError> {
    if value.preset_version != PresetVersion::V1
        || value.authorization_revision == 0
        || value.authorization_revision > i64::MAX as u64
        || value.managed_policy_version > i64::MAX as u64
        || value.expires_at_unix_ms.is_some_and(|expiry| expiry <= 0)
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let mut bytes = Vec::with_capacity(64);
    bytes.push(VERSION);
    bytes.push(mode_tag(value.selected_mode));
    match &value.effective {
        EffectiveModeHistoryState::NotReady(reason) => {
            bytes.push(1);
            bytes.push(not_ready_tag(*reason));
        }
        EffectiveModeHistoryState::Ready {
            mode,
            preset_version,
            scope_digest,
            containment,
        } => {
            if *preset_version != PresetVersion::V1 {
                return Err(PermissionModeStoreError::CorruptData);
            }
            bytes.push(2);
            bytes.push(mode_tag(*mode));
            bytes.extend_from_slice(&preset_version.as_u16().to_be_bytes());
            bytes.extend_from_slice(scope_digest.as_bytes());
            bytes.push(containment_tag(*containment));
        }
    }
    bytes.extend_from_slice(&value.authorization_revision.to_be_bytes());
    bytes.extend_from_slice(&value.preset_version.as_u16().to_be_bytes());
    bytes.extend_from_slice(&value.managed_policy_version.to_be_bytes());
    put_optional_tag(&mut bytes, value.containment.map(containment_tag));
    bytes.push(network_tag(value.network_state));
    match value.expires_at_unix_ms {
        Some(expiry) => {
            bytes.push(1);
            bytes.extend_from_slice(&expiry.to_be_bytes());
        }
        None => bytes.push(0),
    }
    if bytes.len() > 4096 {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(bytes)
}

pub(super) fn decode_history(
    bytes: &[u8],
) -> Result<PermissionModeHistoryProjection, PermissionModeStoreError> {
    let mut reader = Reader { bytes, offset: 0 };
    if reader.byte()? != VERSION {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let selected_mode = mode(reader.byte()?)?;
    let effective = match reader.byte()? {
        1 => EffectiveModeHistoryState::NotReady(not_ready(reader.byte()?)?),
        2 => EffectiveModeHistoryState::Ready {
            mode: mode(reader.byte()?)?,
            preset_version: preset(reader.u16()?)?,
            scope_digest: CompositeScopeDigest::from_bytes(reader.array32()?),
            containment: containment(reader.byte()?)?,
        },
        _ => return Err(PermissionModeStoreError::CorruptData),
    };
    let authorization_revision = reader.u64()?;
    let preset_version = preset(reader.u16()?)?;
    let managed_policy_version = reader.u64()?;
    let containment = match reader.byte()? {
        0 => None,
        1 => Some(containment(reader.byte()?)?),
        _ => return Err(PermissionModeStoreError::CorruptData),
    };
    let network_state = network(reader.byte()?)?;
    let expires_at_unix_ms = match reader.byte()? {
        0 => None,
        1 => Some(reader.i64()?),
        _ => return Err(PermissionModeStoreError::CorruptData),
    };
    if !reader.is_finished()
        || authorization_revision == 0
        || authorization_revision > i64::MAX as u64
        || managed_policy_version > i64::MAX as u64
        || expires_at_unix_ms.is_some_and(|expiry| expiry <= 0)
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(PermissionModeHistoryProjection {
        selected_mode,
        effective,
        authorization_revision,
        preset_version,
        managed_policy_version,
        containment,
        network_state,
        expires_at_unix_ms,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], PermissionModeStoreError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(PermissionModeStoreError::CorruptData)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PermissionModeStoreError::CorruptData)?;
        self.offset = end;
        value
            .try_into()
            .map_err(|_| PermissionModeStoreError::CorruptData)
    }
    fn byte(&mut self) -> Result<u8, PermissionModeStoreError> {
        Ok(self.take::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, PermissionModeStoreError> {
        Ok(u16::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, PermissionModeStoreError> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn i64(&mut self) -> Result<i64, PermissionModeStoreError> {
        Ok(i64::from_be_bytes(self.take()?))
    }
    fn array32(&mut self) -> Result<[u8; 32], PermissionModeStoreError> {
        self.take()
    }
    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn put_optional_tag(bytes: &mut Vec<u8>, value: Option<u8>) {
    match value {
        Some(value) => bytes.extend_from_slice(&[1, value]),
        None => bytes.push(0),
    }
}
fn mode_tag(value: PermissionMode) -> u8 {
    match value {
        PermissionMode::AskAlways => 1,
        PermissionMode::RiskBased => 2,
        PermissionMode::FullAccess => 3,
    }
}
fn mode(value: u8) -> Result<PermissionMode, PermissionModeStoreError> {
    match value {
        1 => Ok(PermissionMode::AskAlways),
        2 => Ok(PermissionMode::RiskBased),
        3 => Ok(PermissionMode::FullAccess),
        _ => Err(PermissionModeStoreError::CorruptData),
    }
}
fn preset(value: u16) -> Result<PresetVersion, PermissionModeStoreError> {
    if value == 1 {
        Ok(PresetVersion::V1)
    } else {
        Err(PermissionModeStoreError::CorruptData)
    }
}
fn not_ready_tag(value: NotReadyReason) -> u8 {
    match value {
        NotReadyReason::NativeContainment => 1,
        NotReadyReason::CompositePolicyUnenforceable => 2,
        NotReadyReason::PresetUnavailable => 3,
    }
}
fn not_ready(value: u8) -> Result<NotReadyReason, PermissionModeStoreError> {
    match value {
        1 => Ok(NotReadyReason::NativeContainment),
        2 => Ok(NotReadyReason::CompositePolicyUnenforceable),
        3 => Ok(NotReadyReason::PresetUnavailable),
        _ => Err(PermissionModeStoreError::CorruptData),
    }
}
fn containment_tag(value: ContainmentStrategy) -> u8 {
    match value {
        ContainmentStrategy::WorkspaceBoundV1 => 1,
        ContainmentStrategy::SameUserCompositeV1 => 2,
        ContainmentStrategy::SameUserCompositeV2 => 3,
    }
}
fn containment(value: u8) -> Result<ContainmentStrategy, PermissionModeStoreError> {
    match value {
        1 => Ok(ContainmentStrategy::WorkspaceBoundV1),
        2 => Ok(ContainmentStrategy::SameUserCompositeV1),
        3 => Ok(ContainmentStrategy::SameUserCompositeV2),
        _ => Err(PermissionModeStoreError::CorruptData),
    }
}

fn network_tag(value: NetworkState) -> u8 {
    match value {
        NetworkState::Unavailable => 1,
        NetworkState::Brokered => 2,
        NetworkState::BroadSameUser => 3,
    }
}
fn network(value: u8) -> Result<NetworkState, PermissionModeStoreError> {
    match value {
        1 => Ok(NetworkState::Unavailable),
        2 => Ok(NetworkState::Brokered),
        3 => Ok(NetworkState::BroadSameUser),
        _ => Err(PermissionModeStoreError::CorruptData),
    }
}

#[cfg(test)]
#[path = "receipt_codec_tests.rs"]
mod tests;
