use super::{containment, containment_tag, decode_history, encode_history};
use crate::store::permission_modes::model::PermissionModeStoreError;
use runne_application::permission_modes::{
    CompositeScopeDigest, ContainmentStrategy, EffectiveModeHistoryState, NetworkState,
    PermissionMode, PermissionModeHistoryProjection, PresetVersion,
};

const NONE: &str = "010202020001111111111111111111111111111111111111111111111111111111111111111103000000000000000400010000000000000007000100";
const WORKSPACE: &str = "010202020001111111111111111111111111111111111111111111111111111111111111111102000000000000000400010000000000000007010102010102030405060708";
const SAME_USER_V1: &str = "01020202000111111111111111111111111111111111111111111111111111111111111111110300000000000000040001000000000000000701020300";
const SAME_USER_V2: &str = "010202020001111111111111111111111111111111111111111111111111111111111111111101000000000000000400010000000000000007010301010000000000000010";

fn projection(
    optional: Option<ContainmentStrategy>,
    effective: ContainmentStrategy,
    network_state: NetworkState,
    expires_at_unix_ms: Option<i64>,
) -> PermissionModeHistoryProjection {
    PermissionModeHistoryProjection {
        selected_mode: PermissionMode::RiskBased,
        effective: EffectiveModeHistoryState::Ready {
            mode: PermissionMode::RiskBased,
            preset_version: PresetVersion::V1,
            scope_digest: CompositeScopeDigest::from_bytes([0x11; 32]),
            containment: effective,
        },
        authorization_revision: 4,
        preset_version: PresetVersion::V1,
        managed_policy_version: 7,
        containment: optional,
        network_state,
        expires_at_unix_ms,
    }
}

#[test]
fn v1_golden_bytes_keep_ready_and_optional_containment_separate() {
    for (golden, expected) in [
        (
            NONE,
            projection(
                None,
                ContainmentStrategy::SameUserCompositeV2,
                NetworkState::Unavailable,
                None,
            ),
        ),
        (
            WORKSPACE,
            projection(
                Some(ContainmentStrategy::WorkspaceBoundV1),
                ContainmentStrategy::SameUserCompositeV1,
                NetworkState::Brokered,
                Some(0x0102_0304_0506_0708),
            ),
        ),
        (
            SAME_USER_V1,
            projection(
                Some(ContainmentStrategy::SameUserCompositeV1),
                ContainmentStrategy::SameUserCompositeV2,
                NetworkState::BroadSameUser,
                None,
            ),
        ),
        (
            SAME_USER_V2,
            projection(
                Some(ContainmentStrategy::SameUserCompositeV2),
                ContainmentStrategy::WorkspaceBoundV1,
                NetworkState::Unavailable,
                Some(16),
            ),
        ),
    ] {
        let bytes = decode_hex(golden);
        assert_eq!(encode_history(&expected).unwrap(), bytes);
        assert_eq!(decode_history(&bytes).unwrap(), expected);
    }
}

#[test]
fn malformed_optional_containment_and_trailing_bytes_are_corrupt() {
    let valid = decode_hex(WORKSPACE);
    for (offset, value) in [(57, 2), (58, 4)] {
        let mut malformed = valid.clone();
        malformed[offset] = value;
        assert_corrupt(&malformed);
    }
    for prefix in [58, 59, 60, valid.len() - 1] {
        assert_corrupt(&valid[..prefix]);
    }
    let mut trailing = valid;
    trailing.push(0);
    assert_corrupt(&trailing);
}

#[test]
fn strategy_tags_keep_legacy_bytes_and_add_v2_symmetrically() {
    for (strategy, tag) in [
        (ContainmentStrategy::WorkspaceBoundV1, 1),
        (ContainmentStrategy::SameUserCompositeV1, 2),
        (ContainmentStrategy::SameUserCompositeV2, 3),
    ] {
        assert_eq!(containment_tag(strategy), tag);
        assert_eq!(containment(tag).unwrap(), strategy);
    }
}

fn assert_corrupt(bytes: &[u8]) {
    assert!(matches!(
        decode_history(bytes),
        Err(PermissionModeStoreError::CorruptData)
    ));
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
