use gocode_opencode_compat::inventory;
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

#[derive(Serialize)]
struct ProfileArtifact {
    profile_id: String,
    profile_revision: u16,
    baseline_sha: String,
    digests: ArtifactInputDigests,
    inventory: Vec<JsonEntry>,
}

#[derive(Serialize)]
struct ArtifactInputDigests {
    profile_schema_digest: String,
    inventory_digest: String,
}

pub fn canonicalize_inventory() -> Vec<u8> {
    let entries = inventory_entries();

    let inventory_digest = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&entries).unwrap())
    );

    let schema_bytes =
        std::fs::read("../../docs/schemas/opencode-baseline-inventory-v1.schema.json").unwrap();
    let schema_digest = format!("sha256:{:x}", Sha256::digest(&schema_bytes));

    let artifact = ProfileArtifact {
        profile_id: "opencode-baseline-inventory".into(),
        profile_revision: 1,
        baseline_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".into(),
        digests: ArtifactInputDigests {
            profile_schema_digest: schema_digest,
            inventory_digest,
        },
        inventory: entries,
    };

    serde_jcs::to_vec(&artifact).unwrap()
}

pub fn canonicalize_profile_v2() -> Vec<u8> {
    let mut entries = inventory_entries();
    let session_create = entries
        .iter_mut()
        .find(|entry| entry.inventory_id == "session.create")
        .expect("session.create inventory entry");
    session_create.classification = "Semantic".into();
    session_create.status = "Verified".into();
    let inventory_digest = format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(&entries).unwrap())
    );
    let schema_bytes =
        std::fs::read("../../docs/schemas/opencode-baseline-inventory-v2.schema.json").unwrap();
    let artifact = ProfileArtifact {
        profile_id: "opencode-baseline-inventory".into(),
        profile_revision: 2,
        baseline_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".into(),
        digests: ArtifactInputDigests {
            profile_schema_digest: format!("sha256:{:x}", Sha256::digest(&schema_bytes)),
            inventory_digest,
        },
        inventory: entries,
    };
    serde_jcs::to_vec(&artifact).unwrap()
}

fn inventory_entries() -> Vec<JsonEntry> {
    inventory::INVENTORY
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
        .collect()
}

pub fn compute_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{:x}", digest)
}
