#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    CommandId, Digest, DurableFixturePromotionAuthority, PromotionStore,
    ThresholdFixtureStoreBinding,
};

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "verify_signed/support.rs"]
mod signing_support;
#[path = "canonical_wire/support.rs"]
mod support;
mod verified_stage_support;

fn path(name: &str) -> std::path::PathBuf {
    std::path::Path::new("/dev/shm").join(format!(
        "gocode-publication-anchor-{name}-{}",
        std::process::id()
    ))
}

fn binding() -> ThresholdFixtureStoreBinding {
    ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap()
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
}

fn lease_path(path: &std::path::Path) -> std::path::PathBuf {
    path.with_extension(
        path.extension()
            .and_then(|value| value.to_str())
            .map_or_else(|| "lease".into(), |value| format!("{value}.lease")),
    )
}

fn replace_string_field(bytes: &[u8], field: &str, replacement: &str) -> Vec<u8> {
    let mut text = String::from_utf8(bytes.to_vec()).unwrap();
    let prefix = format!("\"{field}\":\"");
    let start = text.find(&prefix).unwrap() + prefix.len();
    let end = start + text[start..].find('"').unwrap();
    text.replace_range(start..end, replacement);
    text.into_bytes()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn canonical_json(mut value: serde_json::Value) -> Vec<u8> {
    fn sorted(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for value in map.values_mut() {
                    sorted(value);
                }
                let old = std::mem::take(map);
                map.extend(old);
            }
            serde_json::Value::Array(values) => values.iter_mut().for_each(sorted),
            _ => {}
        }
    }
    sorted(&mut value);
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn reopen_rejects_main_file_rollback_behind_the_protected_anchor() {
    let path = path("rollback");
    cleanup(&path);
    let (mut memory, promotion, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut memory, &promotion, &payloads);
    let mut authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    let older = std::fs::read(&path).unwrap();
    authority
        .reserve_verify_signed(&promotion, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    assert_ne!(std::fs::read(&path).unwrap(), older);
    drop(authority);

    std::fs::write(&path, older).unwrap();
    assert!(DurableFixturePromotionAuthority::reopen(&path, binding()).is_err());
    cleanup(&path);
}

#[test]
fn reopen_repairs_only_the_exact_one_generation_main_successor() {
    let path = path("repair-one");
    cleanup(&path);
    let (mut memory, promotion, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut memory, &promotion, &payloads);
    let mut authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    let anchor_one = std::fs::read(lease_path(&path)).unwrap();
    authority
        .reserve_verify_signed(&promotion, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    let anchor_two = std::fs::read(lease_path(&path)).unwrap();
    drop(authority);

    std::fs::write(lease_path(&path), &anchor_one).unwrap();
    drop(DurableFixturePromotionAuthority::reopen(&path, binding()).unwrap());
    assert_eq!(std::fs::read(lease_path(&path)).unwrap(), anchor_two);
    cleanup(&path);
}

#[test]
fn reopen_rejects_deleted_substituted_or_canonically_tampered_embedded_ledger() {
    let path = path("tamper-matrix");
    cleanup(&path);
    let (memory, _, _) = signing_support::signing_authorized();
    let authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    let original = std::fs::read(&path).unwrap();
    drop(authority);

    let foreign = include_bytes!("fixtures/publication_effect_ledger_v1.json");
    let substituted = replace_string_field(&original, "publication_effect_ledger", &hex(foreign));
    let mut duplicate_namespace: serde_json::Value = serde_json::from_slice(foreign).unwrap();
    let duplicate = duplicate_namespace["claims"][0].clone();
    duplicate_namespace["claims"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    let mut duplicate_command: serde_json::Value = serde_json::from_slice(foreign).unwrap();
    let duplicate = duplicate_command["claims"][0]["commands"][0].clone();
    duplicate_command["claims"][0]["commands"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    let mut changed_freeze: serde_json::Value = serde_json::from_slice(foreign).unwrap();
    changed_freeze["claims"][0]["intent"]["candidate_sha256"] = "99".repeat(32).into();
    let mut inner_unknown: serde_json::Value = serde_json::from_slice(foreign).unwrap();
    inner_unknown["claims"][0]["unknown"] = true.into();
    for bytes in [
        substituted,
        replace_string_field(
            &original,
            "publication_effect_ledger",
            &hex(&canonical_json(duplicate_namespace)),
        ),
        replace_string_field(
            &original,
            "publication_effect_ledger",
            &hex(&canonical_json(duplicate_command)),
        ),
        replace_string_field(
            &original,
            "publication_effect_ledger",
            &hex(&canonical_json(changed_freeze)),
        ),
        replace_string_field(
            &original,
            "publication_effect_ledger",
            &hex(&canonical_json(inner_unknown)),
        ),
        replace_string_field(&original, "authority_instance", &"99".repeat(32)),
        replace_string_field(&original, "profile", "fixture-other"),
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(DurableFixturePromotionAuthority::reopen(&path, binding()).is_err());
    }

    let mut unknown = original.clone();
    unknown.splice(
        unknown.len() - 2..unknown.len() - 2,
        b",\"unknown\":true".iter().copied(),
    );
    std::fs::write(&path, unknown).unwrap();
    assert!(DurableFixturePromotionAuthority::reopen(&path, binding()).is_err());

    let text = String::from_utf8(original).unwrap();
    let field = "\"publication_effect_ledger\":";
    let start = text.find(field).unwrap();
    let end = start + text[start..].find(',').unwrap() + 1;
    let deleted = [&text[..start], &text[end..]].concat();
    std::fs::write(&path, deleted).unwrap();
    assert!(DurableFixturePromotionAuthority::reopen(&path, binding()).is_err());
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn authority_reopen_rejects_empty_unsafe_or_symlinked_anchor_inode() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    for kind in ["empty", "mode", "symlink"] {
        let path = path(kind);
        cleanup(&path);
        let (memory, _, _) = signing_support::signing_authorized();
        let authority =
            DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory)
                .unwrap();
        drop(authority);
        let lease = lease_path(&path);
        match kind {
            "empty" => std::fs::write(&lease, []).unwrap(),
            "mode" => {
                std::fs::set_permissions(&lease, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            "symlink" => {
                std::fs::remove_file(&lease).unwrap();
                let target = path.with_extension("anchor-target");
                std::fs::write(&target, b"not-an-anchor\n").unwrap();
                symlink(&target, &lease).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(DurableFixturePromotionAuthority::reopen(&path, binding()).is_err());
        cleanup(&path);
        let _ = std::fs::remove_file(path.with_extension("anchor-target"));
    }
}

#[test]
fn reopen_rejects_main_file_substitution_from_another_authority() {
    let first = path("substitution-a");
    let second = path("substitution-b");
    cleanup(&first);
    cleanup(&second);
    let (memory_a, _, _) = signing_support::signing_authorized_with("promotion-a");
    let (memory_b, _, _) = signing_support::signing_authorized_with("promotion-b");
    let authority_a =
        DurableFixturePromotionAuthority::create_from_in_memory(&first, binding(), &memory_a)
            .unwrap();
    let authority_b =
        DurableFixturePromotionAuthority::create_from_in_memory(&second, binding(), &memory_b)
            .unwrap();
    let other = std::fs::read(&second).unwrap();
    drop((authority_a, authority_b));
    std::fs::write(&first, other).unwrap();
    assert!(DurableFixturePromotionAuthority::reopen(&first, binding()).is_err());
    cleanup(&first);
    cleanup(&second);
}
