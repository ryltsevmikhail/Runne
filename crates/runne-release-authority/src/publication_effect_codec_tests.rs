use crate::publication_effect_durable::decode_ledger;
use crate::publication_effect_types::PublicationEffectError;

fn golden() -> serde_json::Value {
    serde_json::from_slice(include_bytes!(
        "../tests/fixtures/publication_effect_ledger_v1.json"
    ))
    .unwrap()
}
fn canonical(value: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&crate::wire::sorted_value(value.clone())).unwrap();
    bytes.push(b'\n');
    bytes
}
fn rejected(value: &serde_json::Value) {
    assert!(matches!(
        decode_ledger(&canonical(value)),
        Err(PublicationEffectError::DurableStateUnavailable)
    ));
}

#[test]
fn canonical_decode_rejects_duplicate_logical_keys_and_fingerprints() {
    let mut value = golden();
    let duplicate = value["claims"][0]["commands"][0].clone();
    value["claims"][0]["commands"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    rejected(&value);
}

#[test]
fn canonical_decode_rejects_mismatched_namespace_generation_and_incomplete_outcome() {
    let mut value = golden();
    value["claims"][0]["namespace"] = "ns-2".into();
    rejected(&value);
    let mut value = golden();
    value["claims"][0]["commands"][0]["outcome"]["generation"] = 2.into();
    rejected(&value);
    let mut value = golden();
    value["claims"][0]["commands"][0]
        .as_object_mut()
        .unwrap()
        .remove("outcome");
    rejected(&value);
}

#[test]
fn canonical_decode_rejects_illegal_state_outcome_and_tombstone_combinations() {
    let mut value = golden();
    value["claims"][0]["state"] = "succeeded".into();
    rejected(&value);
    let mut value = golden();
    value["claims"][0]["commands"][0]["outcome"]["state"] = "in_flight".into();
    rejected(&value);
    let mut value = golden();
    value["claims"][0]["settlement_sha256"] = "aa".repeat(32).into();
    rejected(&value);
    let mut value = golden();
    value["claims"][0]["commands"][0]["command_fingerprint_sha256"] = "aa".repeat(32).into();
    rejected(&value);
}

#[test]
fn canonical_decode_requires_exact_bytes_and_one_lf() {
    let golden = include_bytes!("../tests/fixtures/publication_effect_ledger_v1.json");
    let mut no_lf = golden.to_vec();
    no_lf.pop();
    assert!(matches!(
        decode_ledger(&no_lf),
        Err(PublicationEffectError::DurableStateUnavailable)
    ));
    let mut extra = golden.to_vec();
    extra.push(b'\n');
    assert!(matches!(
        decode_ledger(&extra),
        Err(PublicationEffectError::DurableStateUnavailable)
    ));
}
