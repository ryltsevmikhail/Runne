use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;

const D: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const P: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const Z: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn metadata(inventory: &str) -> Value {
    metadata_with_targets(inventory, [(P, 11), (P, 22), (P, 55)])
}

pub fn metadata_with_targets(inventory: &str, post: [(&str, u64); 3]) -> Value {
    let root = root_body(inventory);
    let root_raw = canonical(&root);
    let targets = targets_body(inventory, &root_raw, post);
    let targets_raw = canonical(&targets);
    let snapshot = online_body("snapshot", inventory, &targets_raw, 2, "snapshot");
    let snapshot_raw = canonical(&snapshot);
    let timestamp = online_body("timestamp", inventory, &snapshot_raw, 2, "timestamp");
    json!({"schema_version":"gocode.release.rc2-threshold-update-metadata-set/2",
        "root":{"body":root,"successor_authorization":[proof("root-successor","r1",1,&root_raw),proof("root-successor","r2",2,&root_raw)],"self_proof":[proof("root-self","r1",1,&root_raw),proof("root-self","r2",2,&root_raw)]},
        "targets":{"body":targets,"root_authorization":[proof("targets-root","r1",1,&targets_raw),proof("targets-root","r2",2,&targets_raw)],"self_proof":[proof("targets-self","t1",4,&targets_raw),proof("targets-self","t2",5,&targets_raw)]},
        "snapshot":{"body":snapshot,"signature":proof("snapshot","snapshot",7,&snapshot_raw)},
        "timestamp":{"body":timestamp,"signature":proof("timestamp","timestamp",8,&canonical(&timestamp))}})
}

#[allow(dead_code)]
pub fn rotated_metadata(inventory: &str, predecessor: &str, predecessor_keys: &str) -> Value {
    let mut root = root_body(inventory);
    replace(&mut root, "version", json!(3));
    replace(&mut root, "keyset", keyset("n", 11));
    replace(&mut root, "predecessor_body_sha256", json!(predecessor));
    replace(
        &mut root,
        "predecessor_keyset_sha256",
        json!(predecessor_keys),
    );
    let root_raw = canonical(&root);
    let mut targets = targets_body(inventory, &root_raw, [(P, 11), (P, 22), (P, 55)]);
    replace(&mut targets, "version", json!(3));
    replace(&mut targets, "root_version", json!(3));
    replace(&mut targets, "keyset", keyset("u", 14));
    let targets_raw = canonical(&targets);
    let snapshot = online_body("snapshot", inventory, &targets_raw, 3, "snapshot");
    let snapshot_raw = canonical(&snapshot);
    let timestamp = online_body("timestamp", inventory, &snapshot_raw, 3, "timestamp");
    json!({"schema_version":"gocode.release.rc2-threshold-update-metadata-set/2",
        "root":{"body":root,"successor_authorization":[proof("root-successor","r1",1,&root_raw),proof("root-successor","r2",2,&root_raw)],"self_proof":[proof("root-self","n1",11,&root_raw),proof("root-self","n2",12,&root_raw)]},
        "targets":{"body":targets,"root_authorization":[proof("targets-root","n1",11,&targets_raw),proof("targets-root","n2",12,&targets_raw)],"self_proof":[proof("targets-self","u1",14,&targets_raw),proof("targets-self","u2",15,&targets_raw)]},
        "snapshot":{"body":snapshot,"signature":proof("snapshot","snapshot",7,&snapshot_raw)},
        "timestamp":{"body":timestamp,"signature":proof("timestamp","timestamp",8,&canonical(&timestamp))}})
}

#[allow(dead_code)]
pub fn root_body_bytes(inventory: &str) -> Vec<u8> {
    canonical(&root_body(inventory))
}

#[allow(dead_code)]
pub fn root_keyset_digest() -> String {
    let mut transcript = b"gocode.release.rc2-threshold-keyset/2\0".to_vec();
    for offset in 0..3 {
        let id = format!("r{}", offset + 1);
        let key = SigningKey::from_bytes(&[offset + 1; 32])
            .verifying_key()
            .to_bytes();
        transcript.extend_from_slice(&(id.len() as u64).to_be_bytes());
        transcript.extend_from_slice(id.as_bytes());
        transcript.extend_from_slice(&(key.len() as u64).to_be_bytes());
        transcript.extend_from_slice(&key);
    }
    hash(&transcript)
}

fn root_body(inventory: &str) -> Value {
    map(vec![
        ("role", json!("root")),
        ("candidate_sha256", json!(D)),
        ("inventory_sha256", json!(inventory)),
        ("version", json!(2)),
        ("rollback_floor", json!(1)),
        ("expires_at", json!(2)),
        ("revocation_epoch", json!(1)),
        ("frozen", json!(false)),
        ("keyset", keyset("r", 1)),
        ("predecessor_body_sha256", json!(Z)),
        ("predecessor_keyset_sha256", json!(Z)),
    ])
}
fn targets_body(inventory: &str, root: &[u8], post: [(&str, u64); 3]) -> Value {
    map(vec![
        ("role", json!("targets")),
        ("candidate_sha256", json!(D)),
        ("inventory_sha256", json!(inventory)),
        ("version", json!(2)),
        ("rollback_floor", json!(1)),
        ("expires_at", json!(2)),
        ("revocation_epoch", json!(1)),
        ("frozen", json!(false)),
        ("keyset", keyset("t", 4)),
        ("root_body_sha256", json!(hash(root))),
        ("root_body_length", json!(root.len())),
        ("root_version", json!(2)),
        (
            "targets",
            json!([
                target("linux-appimage", "linux", "x86_64", post[0]),
                target("linux-deb", "linux", "x86_64", post[1]),
                target("windows-installer-unsigned", "windows", "x86_64", post[2])
            ]),
        ),
    ])
}
fn online_body(role: &str, inventory: &str, predecessor: &[u8], version: u64, key: &str) -> Value {
    map(vec![
        ("role", json!(role)),
        ("candidate_sha256", json!(D)),
        ("inventory_sha256", json!(inventory)),
        ("version", json!(version)),
        ("rollback_floor", json!(1)),
        ("expires_at", json!(2)),
        ("revocation_epoch", json!(1)),
        ("frozen", json!(false)),
        ("key_id", json!(key)),
        ("predecessor_body_sha256", json!(hash(predecessor))),
        ("predecessor_body_length", json!(predecessor.len())),
        ("predecessor_version", json!(version)),
    ])
}
fn target(slot: &str, platform: &str, architecture: &str, post: (&str, u64)) -> Value {
    map(vec![
        ("slot", json!(slot)),
        ("app_version", json!("1.0.0")),
        ("release_sequence", json!(1)),
        ("bundle_id", json!("gocode-desktop")),
        ("platform", json!(platform)),
        ("architecture", json!(architecture)),
        ("artifact_sha256", json!(post.0)),
        ("artifact_length", json!(post.1)),
        ("min_os_policy_id", json!("v1-minimum-os")),
        ("min_os_policy_sha256", json!(D)),
        (
            "profiles",
            json!([{"profile_id":"gocode-bundled-runtime","bundle_sha256":D}]),
        ),
        ("runtime_version", json!("1.0.0")),
        ("runtime_sha256", json!(D)),
        ("channel_selector", json!("fixture-channel-policy")),
    ])
}
fn keyset(prefix: &str, first: u8) -> Value {
    json!((0..3).map(|offset| json!({"key_id":format!("{prefix}{}",offset+1),"public_key":hex(SigningKey::from_bytes(&[first+offset;32]).verifying_key().to_bytes())})).collect::<Vec<_>>())
}
fn map(items: Vec<(&str, Value)>) -> Value {
    json!(items.into_iter().collect::<BTreeMap<_, _>>())
}
#[allow(dead_code)]
fn replace(value: &mut Value, key: &str, next: Value) {
    value.as_object_mut().unwrap().insert(key.into(), next);
}
fn canonical(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn hash(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).into())
}

pub fn proof(role: &str, key_id: &str, seed: u8, unsigned: &[u8]) -> Value {
    let mut transcript = b"gocode.release.rc2-threshold-signature/1\0".to_vec();
    transcript.extend_from_slice(role.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(unsigned);
    json!({"key_id":key_id,"signature":hex(SigningKey::from_bytes(&[seed;32]).sign(&transcript).to_bytes())})
}
fn hex<const N: usize>(bytes: [u8; N]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(N * 2), |mut text, byte| {
            write!(text, "{byte:02x}").expect("writing to String cannot fail");
            text
        })
}
