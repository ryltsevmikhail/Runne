use gocode_opencode_compat::inventory;
use gocode_opencode_compat::profile::Transport;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct JsonEntry {
    inventory_id: String,
    upstream_operation_id: Option<String>,
    method: String,
    normalized_path: String,
    transport: String,
    classification: String,
    status: String,
}

pub fn canonicalize_inventory() -> Vec<u8> {
    let entries: Vec<_> = inventory::INVENTORY
        .iter()
        .map(|e| JsonEntry {
            inventory_id: e.inventory_id.clone(),
            upstream_operation_id: e.upstream_operation_id.clone(),
            method: e.selector.method.clone(),
            normalized_path: e.selector.normalized_path.clone(),
            transport: format!("{:?}", e.transport),
            classification: format!("{:?}", e.classification),
            status: format!("{:?}", e.implementation_status),
        })
        .collect();
    let value = serde_json::to_value(&entries).unwrap();
    serde_jcs::to_vec(&value).unwrap()
}

pub fn compute_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{:x}", digest)
}
