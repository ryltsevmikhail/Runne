use runne_release_authority::{AuthorityError, CanonicalPayloadKind, InspectedCanonicalPayload};

#[path = "canonical_wire/kinds.rs"]
mod kinds;
#[path = "canonical_wire/support.rs"]
mod support;

use kinds::KINDS;
use support::payload;

#[test]
fn accepts_full_canonical_64hex_vectors_and_binds_raw_hash() {
    for kind in KINDS.into_iter().filter(|kind| !is_legacy_rc3(*kind)) {
        let raw = payload(kind);
        let parsed = InspectedCanonicalPayload::parse(kind, &raw)
            .unwrap_or_else(|error| panic!("{kind:?}: {error:?}"));
        assert_eq!(parsed.raw(), raw);
        assert_ne!(parsed.sha256(), [0; 32]);
    }
}

#[test]
fn rejects_noncanonical_and_nested_duplicate_forms_for_every_type() {
    for kind in KINDS.into_iter().filter(|kind| !is_legacy_rc3(*kind)) {
        let raw = payload(kind);
        let text = String::from_utf8(raw).unwrap();
        let reordered = text.replacen('{', "{ ", 1);
        let crlf = text.replace('\n', "\r\n");
        let missing_lf = text.trim_end().to_owned();
        let duplicate = text.replacen('{', "{\"schema_version\":\"duplicate\",", 1);
        let unknown = text.replacen('}', ",\"unknown\":true}", 1);
        let nested = if kind == CanonicalPayloadKind::Rc1Decision {
            text.replace(
                "\"account_id\":\"account\"",
                "\"account_id\":\"account\",\"account_id\":\"duplicate\"",
            )
        } else {
            duplicate.clone()
        };
        let mut missing_value: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&text).unwrap();
        let first_name = missing_value.keys().next().unwrap().to_owned();
        missing_value.remove(&first_name);
        let mut missing = serde_json::to_vec(&missing_value).unwrap();
        missing.push(b'\n');
        for bad in [
            reordered.into_bytes(),
            crlf.into_bytes(),
            missing_lf.into_bytes(),
            duplicate.into_bytes(),
            unknown.into_bytes(),
            missing,
            nested.into_bytes(),
        ] {
            assert_eq!(
                InspectedCanonicalPayload::parse(kind, &bad),
                Err(AuthorityError::NonCanonicalPayload)
            );
        }
    }
}

#[test]
fn rejects_wrong_consts_types_u64_and_unsafe_identifiers() {
    let bad = [
        (
            CanonicalPayloadKind::Rc1Decision,
            "\"signing_allowed\":false",
            "\"signing_allowed\":true",
        ),
        (
            CanonicalPayloadKind::ArtifactRecord,
            "\"artifact_length\":18446744073709551615",
            "\"artifact_length\":-1",
        ),
        (
            CanonicalPayloadKind::Rc2Authorization,
            "\"runner-principal\"",
            "\"bad space\"",
        ),
        (
            CanonicalPayloadKind::Snapshot,
            "\"revision\":18446744073709551615",
            "\"revision\":18446744073709551616",
        ),
    ];
    for (kind, expected, replacement) in bad {
        let raw = String::from_utf8(payload(kind))
            .unwrap()
            .replace(expected, replacement);
        assert_eq!(
            InspectedCanonicalPayload::parse(kind, raw.as_bytes()),
            Err(AuthorityError::NonCanonicalPayload)
        );
    }
}

#[test]
fn threshold_metadata_without_detached_signature_evidence_is_rejected() {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/threshold_v2_valid.json")).unwrap();
    let mut valid = serde_json::to_vec(&value).unwrap();
    valid.push(b'\n');
    assert!(
        InspectedCanonicalPayload::parse(CanonicalPayloadKind::ThresholdMetadata, &valid).is_ok()
    );
    let mut value = value.as_object().unwrap().clone();
    value
        .get_mut("root")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap()
        .remove("self_proof");
    let mut raw = serde_json::to_vec(&value).unwrap();
    raw.push(b'\n');
    assert_eq!(
        InspectedCanonicalPayload::parse(CanonicalPayloadKind::ThresholdMetadata, &raw),
        Err(AuthorityError::NonCanonicalPayload)
    );
}

#[test]
fn active_rc2_record_parser_rejects_legacy_record_v1_as_superseded() {
    let raw = String::from_utf8(payload(CanonicalPayloadKind::ArtifactRecord))
        .unwrap()
        .replace("record/2", "record/1");
    assert_eq!(
        InspectedCanonicalPayload::parse(CanonicalPayloadKind::ArtifactRecord, raw.as_bytes()),
        Err(AuthorityError::AuthorityVersionSuperseded)
    );
}

#[test]
fn active_rc3_parser_rejects_legacy_publication_manifest_and_authorization_v1_as_superseded() {
    for kind in [
        CanonicalPayloadKind::PublicationManifest,
        CanonicalPayloadKind::Rc3Authorization,
    ] {
        let raw = payload(kind);
        assert_eq!(
            InspectedCanonicalPayload::parse(kind, &raw),
            Err(AuthorityError::AuthorityVersionSuperseded)
        );
    }
}

#[test]
fn threshold_metadata_rejects_broken_role_links_and_missing_rotation_proofs() {
    let raw = payload(CanonicalPayloadKind::ThresholdMetadata);
    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    for missing in [
        ["root", "self_proof"],
        ["root", "successor_authorization"],
        ["targets", "root_authorization"],
        ["targets", "self_proof"],
    ] {
        let mut invalid = value.clone();
        invalid
            .get_mut(missing[0])
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .remove(missing[1]);
        let mut raw = serde_json::to_vec(&invalid).unwrap();
        raw.push(b'\n');
        assert_eq!(
            InspectedCanonicalPayload::parse(CanonicalPayloadKind::ThresholdMetadata, &raw),
            Err(AuthorityError::NonCanonicalPayload),
            "{missing:?}"
        );
    }
    let mut invalid = value;
    invalid["targets"]["body"]
        .as_object_mut()
        .unwrap()
        .insert("root_body_length".into(), serde_json::json!(1));
    let mut raw = serde_json::to_vec(&invalid).unwrap();
    raw.push(b'\n');
    assert_eq!(
        InspectedCanonicalPayload::parse(CanonicalPayloadKind::ThresholdMetadata, &raw),
        Err(AuthorityError::NonCanonicalPayload)
    );
}

#[test]
fn threshold_v2_rejects_role_slot_key_and_proof_mutation_corpus() {
    let value: serde_json::Value =
        serde_json::from_slice(&payload(CanonicalPayloadKind::ThresholdMetadata)).unwrap();
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/threshold_v2_mutations.json")).unwrap();
    for mutation in corpus.as_array().unwrap() {
        if !mutation["rust_reject"].as_bool().unwrap() {
            continue;
        }
        let mut invalid = value.clone();
        set(
            &mut invalid,
            mutation["path"].as_array().unwrap(),
            mutation["value"].clone(),
        );
        let mut raw = serde_json::to_vec(&invalid).unwrap();
        raw.push(b'\n');
        assert_eq!(
            InspectedCanonicalPayload::parse(CanonicalPayloadKind::ThresholdMetadata, &raw),
            Err(AuthorityError::NonCanonicalPayload),
            "{}",
            mutation["name"]
        );
    }
}

const fn is_legacy_rc3(kind: CanonicalPayloadKind) -> bool {
    matches!(
        kind,
        CanonicalPayloadKind::PublicationManifest | CanonicalPayloadKind::Rc3Authorization
    )
}

fn set(value: &mut serde_json::Value, path: &[serde_json::Value], next: serde_json::Value) {
    let segment = path[0].as_str().unwrap();
    if path.len() == 1 {
        *value.get_mut(segment).unwrap() = next;
    } else if let Ok(index) = segment.parse::<usize>() {
        set(&mut value[index], &path[1..], next);
    } else {
        set(value.get_mut(segment).unwrap(), &path[1..], next);
    }
}

#[test]
fn threshold_metadata_rejects_the_superseded_aggregate_signature_body() {
    let raw = b"{\"schema_version\":\"gocode.release.rc2-threshold-update-metadata-set/1\",\"candidate_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n";
    assert_eq!(
        InspectedCanonicalPayload::parse(CanonicalPayloadKind::ThresholdMetadata, raw),
        Err(AuthorityError::NonCanonicalPayload)
    );
}
