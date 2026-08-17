#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    AuthorityError, CommandId, Digest, DurableFixtureThresholdContext, PromotionStore,
    ThresholdFixtureStoreBinding, ThresholdVerificationState, admit_prevalidated_signed_bundle,
};
use sha2::{Digest as _, Sha256};

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "verify_signed/support.rs"]
mod signing_support;
#[path = "canonical_wire/support.rs"]
mod support;
#[path = "threshold_support.rs"]
mod threshold_support;
mod verified_stage_support;

#[test]
fn same_journal_key_with_any_changed_scope_field_is_immutable_after_reopen() {
    for field in 4..10 {
        let path = std::env::temp_dir().join(format!(
            "gocode-threshold-unique-{field}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let binding = binding();
        let context =
            DurableFixtureThresholdContext::create(&path, binding.clone(), state(), 1).unwrap();
        let instance = Digest::fixture([0x22; 32]);
        let (mut store, id, payloads) =
            signing_support::signing_authorized_in_authority("p", instance);
        let (mut retry, retry_id, _) =
            signing_support::signing_authorized_in_authority("p", instance);
        let bundle = signing_support::leased_bundle(&mut retry, &retry_id, &payloads);
        let receipt = retry
            .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
            .unwrap();
        admit_prevalidated_signed_bundle(bundle, receipt, &context).unwrap();
        drop(context);
        change_scope_field(&path, field);
        let before = std::fs::read(&path).unwrap();
        let context = DurableFixtureThresholdContext::reopen(&path, binding).unwrap();
        let bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
        let receipt = store
            .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
            .unwrap();
        assert_eq!(
            admit_prevalidated_signed_bundle(bundle, receipt, &context),
            Err(AuthorityError::BindingMismatch),
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "field {field}");
        drop(context);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(path.with_extension("lease")).unwrap();
    }
}

#[test]
fn reopen_rejects_duplicate_logical_journal_keys_before_recovery() {
    for divergent in [false, true] {
        let path = std::env::temp_dir().join(format!(
            "gocode-threshold-duplicate-{divergent}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let binding = binding();
        let context =
            DurableFixtureThresholdContext::create(&path, binding.clone(), state(), 1).unwrap();
        let (mut store, id, payloads) = signing_support::signing_authorized();
        let bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
        let receipt = store
            .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
            .unwrap();
        admit_prevalidated_signed_bundle(bundle, receipt, &context).unwrap();
        drop(context);
        duplicate_journal(&path, divergent);
        assert!(
            DurableFixtureThresholdContext::reopen(&path, binding).is_err(),
            "divergent={divergent}"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(path.with_extension("lease")).unwrap();
    }
}

#[test]
fn rotated_root_requires_old_and_new_quorums_then_reopens_existing_same() {
    let path =
        std::env::temp_dir().join(format!("gocode-threshold-rotation-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let instance = Digest::fixture([0x23; 32]);
    let (mut store, id, payloads) = signing_support::signing_authorized_in_authority("p", instance);
    let rotated = rotation_payloads(payloads);
    let context =
        DurableFixtureThresholdContext::create(&path, binding(), rotated_state(&rotated), 1)
            .unwrap();
    let (mut retry, retry_id, _) = signing_support::signing_authorized_in_authority("p", instance);
    let bundle = signing_support::leased_bundle(&mut retry, &retry_id, &rotated);
    let receipt = retry
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    let first = admit_prevalidated_signed_bundle(bundle, receipt, &context).unwrap();
    let persisted = context.state().unwrap();
    assert_eq!(persisted.versions["root"], 3);
    assert!(persisted.root_keys.contains_key("n1"));
    assert_eq!(persisted.role_bodies.len(), 4);
    drop(context);
    let context = DurableFixtureThresholdContext::reopen(&path, binding()).unwrap();
    let bundle = signing_support::leased_bundle(&mut store, &id, &rotated);
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    assert_eq!(
        admit_prevalidated_signed_bundle(bundle, receipt, &context).unwrap(),
        first
    );
    assert_eq!(context.state().unwrap(), persisted);
    drop(context);
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(path.with_extension("lease")).unwrap();
}

fn change_scope_field(path: &std::path::Path, field: usize) {
    let text = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
    let changed = text
        .lines()
        .map(|line| {
            let Some(scope) = line.strip_prefix("journal_scope=") else {
                return line.into();
            };
            let mut fields = scope.split('@').map(String::from).collect::<Vec<_>>();
            fields[field] = "bb".repeat(32);
            format!("journal_scope={}", fields.join("@"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, format!("{changed}\n")).unwrap();
}

fn duplicate_journal(path: &std::path::Path, divergent: bool) {
    let text = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
    let (head, tail) = text.split_once("ack_count=").unwrap();
    let index = head.find("journal_scope=").unwrap();
    let entry = &head[index..];
    let duplicate = if divergent {
        let mut lines = entry.lines().map(String::from).collect::<Vec<_>>();
        let mut fields = lines[0]
            .strip_prefix("journal_scope=")
            .unwrap()
            .split('@')
            .map(String::from)
            .collect::<Vec<_>>();
        fields[4] = "bb".repeat(32);
        lines[0] = format!("journal_scope={}", fields.join("@"));
        format!("{}\n", lines.join("\n"))
    } else {
        entry.into()
    };
    let head = head.replacen("journal_count=1", "journal_count=2", 1);
    std::fs::write(path, format!("{head}{duplicate}ack_count={tail}")).unwrap();
}

fn binding() -> ThresholdFixtureStoreBinding {
    ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap()
}

fn state() -> ThresholdVerificationState {
    ThresholdVerificationState {
        versions: ["root", "targets", "snapshot", "timestamp"]
            .into_iter()
            .map(|role| (role.into(), 1))
            .collect(),
        rollback_floor: 1,
        revocation_floor: 1,
        frozen: false,
        generation: 1,
        root_keys: threshold_support::threshold_keyset("r"),
        targets_keys: threshold_support::threshold_keyset("t"),
        snapshot_key: (
            "snapshot".into(),
            threshold_support::threshold_public_key("snapshot"),
        ),
        timestamp_key: (
            "timestamp".into(),
            threshold_support::threshold_public_key("timestamp"),
        ),
        channel_policy_id: Some("fixture-channel-policy".into()),
        role_bodies: std::collections::BTreeMap::new(),
        role_digests: std::collections::BTreeMap::new(),
    }
}

fn rotated_state(
    payloads: &[(gocode_release_authority::CanonicalPayloadKind, Vec<u8>)],
) -> ThresholdVerificationState {
    let inventory = payloads
        .iter()
        .find(|(kind, _)| *kind == gocode_release_authority::CanonicalPayloadKind::Inventory)
        .unwrap();
    let body = support::threshold_fixture::root_body_bytes(&hex(&inventory.1));
    ThresholdVerificationState {
        versions: ["root", "targets", "snapshot", "timestamp"]
            .into_iter()
            .map(|role| (role.into(), 2))
            .collect(),
        generation: 1,
        role_digests: std::iter::once((
            "root".into(),
            Digest::fixture(Sha256::digest(&body).into()),
        ))
        .collect(),
        role_bodies: std::iter::once(("root".into(), body)).collect(),
        ..state()
    }
}

fn rotation_payloads(
    mut payloads: Vec<(gocode_release_authority::CanonicalPayloadKind, Vec<u8>)>,
) -> Vec<(gocode_release_authority::CanonicalPayloadKind, Vec<u8>)> {
    let inventory = payloads
        .iter()
        .find(|(kind, _)| *kind == gocode_release_authority::CanonicalPayloadKind::Inventory)
        .unwrap();
    let metadata = support::threshold_fixture::rotated_metadata(
        &hex(&inventory.1),
        &hex(&support::threshold_fixture::root_body_bytes(&hex(
            &inventory.1,
        ))),
        &support::threshold_fixture::root_keyset_digest(),
    );
    let mut raw = serde_json::to_vec(&metadata).unwrap();
    raw.push(b'\n');
    let metadata_digest = hex(&raw);
    for (kind, bytes) in &mut payloads {
        if *kind == gocode_release_authority::CanonicalPayloadKind::ThresholdMetadata {
            bytes.clone_from(&raw);
        } else if *kind == gocode_release_authority::CanonicalPayloadKind::VerificationReport {
            let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            value["metadata_set_sha256"] = serde_json::json!(metadata_digest);
            *bytes = serde_json::to_vec(&value).unwrap();
            bytes.push(b'\n');
        }
    }
    payloads
}

fn hex(raw: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(raw.strip_suffix(b"\n").unwrap_or(raw))
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            write!(text, "{byte:02x}").unwrap();
            text
        })
}
