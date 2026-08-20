use runne_project_owner_authority::{
    AuthorityError, Document, GitSubject, SigningDomain, UnsignedReceipt,
    canonical_unsigned_receipt, signing_transcript,
};

fn receipt() -> UnsignedReceipt {
    UnsignedReceipt {
        schema_version: "gocode.project-owner.authority-receipt/1".to_owned(),
        repository_id: "gocode".to_owned(),
        role: "PROJECT_OWNER".to_owned(),
        purpose: "V1_PLATFORM_SCOPE_AUTHORIZATION".to_owned(),
        trust_config_sha256: "a".repeat(64),
        key_id: "b".repeat(64),
        key_epoch: 1,
        subject: GitSubject {
            object_format: "sha1".to_owned(),
            commit_oid: "c".repeat(40),
            tree_oid: "d".repeat(40),
        },
        documents: vec![
            Document {
                path: "docs/z.json".to_owned(),
                mode: "100644".to_owned(),
                blob_oid: "e".repeat(40),
                content_sha256: "f".repeat(64),
                byte_length: 2,
                schema_id: None,
            },
            Document {
                path: "docs/a.json".to_owned(),
                mode: "100644".to_owned(),
                blob_oid: "1".repeat(40),
                content_sha256: "2".repeat(64),
                byte_length: 1,
                schema_id: Some("gocode.example/1".to_owned()),
            },
        ],
        issued_at: "2026-08-12T00:00:00Z".to_owned(),
        profile: "gocode.project-owner.v1-platform-scope/1".to_owned(),
    }
}

#[test]
fn canonical_receipt_sorts_keys_documents_and_ends_with_one_lf() {
    let canonical = canonical_unsigned_receipt(&receipt()).expect("canonical receipt");
    let expected = concat!(
        "{\"documents\":[{\"blob_oid\":\"1111111111111111111111111111111111111111\",\"byte_length\":1,\"content_sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"mode\":\"100644\",\"path\":\"docs/a.json\",\"schema_id\":\"gocode.example/1\"},{\"blob_oid\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"byte_length\":2,\"content_sha256\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"mode\":\"100644\",\"path\":\"docs/z.json\"}],",
        "\"issued_at\":\"2026-08-12T00:00:00Z\",\"key_epoch\":1,\"key_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"profile\":\"gocode.project-owner.v1-platform-scope/1\",\"purpose\":\"V1_PLATFORM_SCOPE_AUTHORIZATION\",\"repository_id\":\"gocode\",\"role\":\"PROJECT_OWNER\",\"schema_version\":\"gocode.project-owner.authority-receipt/1\",\"subject\":{\"commit_oid\":\"cccccccccccccccccccccccccccccccccccccccc\",\"object_format\":\"sha1\",\"tree_oid\":\"dddddddddddddddddddddddddddddddddddddddd\"},\"trust_config_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n"
    )
    .as_bytes();

    assert_eq!(canonical, expected);
    assert_eq!(canonical.last(), Some(&b'\n'));
    assert!(!canonical[..canonical.len() - 1].contains(&b'\n'));
}

#[test]
fn canonical_receipt_rejects_duplicate_document_paths() {
    let mut duplicate = receipt();
    duplicate.documents[1].path = duplicate.documents[0].path.clone();

    assert!(matches!(
        canonical_unsigned_receipt(&duplicate),
        Err(AuthorityError::DuplicateDocumentPath(path)) if path == "docs/z.json"
    ));
}

#[test]
fn strict_parser_rejects_duplicate_and_unknown_fields_before_deserialization() {
    let duplicate = br#"{"schema_version":"one","schema_version":"two"}"#;
    assert!(matches!(
        UnsignedReceipt::from_json(duplicate),
        Err(AuthorityError::DuplicateKey(key)) if key == "schema_version"
    ));

    let unknown = br#"{"schema_version":"one","unexpected":true}"#;
    assert!(matches!(
        UnsignedReceipt::from_json(unknown),
        Err(AuthorityError::UnknownField(key)) if key == "unexpected"
    ));
}

#[test]
fn strict_parser_rejects_invalid_utf8() {
    assert!(matches!(
        UnsignedReceipt::from_json(&[b'{', 0xff, b'}']),
        Err(AuthorityError::InvalidUtf8)
    ));
}

#[test]
fn strict_parser_rejects_duplicate_document_paths() {
    let mut value = serde_json::to_value(receipt()).expect("receipt JSON");
    let documents = value["documents"].as_array_mut().expect("documents array");
    documents[1]["path"] = documents[0]["path"].clone();
    let input = serde_json::to_vec(&value).expect("duplicate document JSON");

    assert!(matches!(
        UnsignedReceipt::from_json(&input),
        Err(AuthorityError::DuplicateDocumentPath(path)) if path == "docs/z.json"
    ));
}

#[test]
fn transcript_has_hand_authored_length_prefixes_and_domain_separation() {
    let domain = SigningDomain::new(
        "gocode.project-owner.authority-receipt/1",
        "V1_PLATFORM_SCOPE_AUTHORIZATION",
        "gocode",
    )
    .expect("bounded domain");
    let expected_bytes = [
        &106_u32.to_be_bytes()[..],
        &40_u32.to_be_bytes(),
        b"gocode.project-owner.authority-receipt/1",
        &31_u32.to_be_bytes(),
        b"V1_PLATFORM_SCOPE_AUTHORIZATION",
        &6_u32.to_be_bytes(),
        b"gocode",
        &13_u32.to_be_bytes(),
        b"PROJECT_OWNER",
        &2_u64.to_be_bytes(),
        b"{}",
    ]
    .concat();

    assert_eq!(signing_transcript(&domain, b"{}"), expected_bytes);
    let changed = SigningDomain::new(
        "gocode.project-owner.authority-receipt/1",
        "OTHER_PURPOSE",
        "gocode",
    )
    .expect("bounded domain");
    assert_ne!(
        signing_transcript(&domain, b"{}"),
        signing_transcript(&changed, b"{}")
    );
}
