use super::*;

const KEY_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const KEY_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const KEY_C: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const KEY_D: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const KEY_E: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const NON_HEX_KEY: &str = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
const LONG_KEY: &str = "111111111111111111111111111111111111111111111111111111111111111111";

fn values() -> CompiledUpdateTrustRootValues {
    CompiledUpdateTrustRootValues {
        root_a_id: Some("root-a"), root_b_id: Some("root-b"), root_c_id: Some("root-c"),
        timestamp_id: Some("timestamp"), snapshot_id: Some("snapshot"),
        root_a_hex: Some(KEY_A), root_b_hex: Some(KEY_B), root_c_hex: Some(KEY_C),
        timestamp_hex: Some(KEY_D), snapshot_hex: Some(KEY_E),
    }
}

#[test]
fn compiled_update_trust_requires_every_field_and_exact_public_keys() {
    assert!(CompiledUpdateTrustRootV2::from_values(&values()).is_some());
    let key_setters: [fn(&mut CompiledUpdateTrustRootValues, &'static str); 5] = [
        |value, key| value.root_a_hex = Some(key), |value, key| value.root_b_hex = Some(key),
        |value, key| value.root_c_hex = Some(key), |value, key| value.timestamp_hex = Some(key),
        |value, key| value.snapshot_hex = Some(key),
    ];
    for malformed_key in ["11", NON_HEX_KEY, LONG_KEY] {
        for set_key in key_setters {
            let mut malformed = values();
            set_key(&mut malformed, malformed_key);
            assert!(CompiledUpdateTrustRootV2::from_values(&malformed).is_none());
        }
    }
    let omissions: [fn(&mut CompiledUpdateTrustRootValues); 10] = [
        |value| value.root_a_id = None, |value| value.root_b_id = None,
        |value| value.root_c_id = None, |value| value.timestamp_id = None,
        |value| value.snapshot_id = None, |value| value.root_a_hex = None,
        |value| value.root_b_hex = None, |value| value.root_c_hex = None,
        |value| value.timestamp_hex = None, |value| value.snapshot_hex = None,
    ];
    for omit in omissions {
        let mut absent = values();
        omit(&mut absent);
        assert!(CompiledUpdateTrustRootV2::from_values(&absent).is_none());
    }
}
