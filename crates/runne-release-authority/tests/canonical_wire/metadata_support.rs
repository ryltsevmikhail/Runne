pub fn threshold_metadata_for_inventory(inventory_sha256: &str) -> Vec<u8> {
    let mut raw = serde_json::to_vec(&super::support::threshold_fixture::metadata(
        inventory_sha256,
    ))
    .expect("metadata JSON");
    raw.push(b'\n');
    raw
}
