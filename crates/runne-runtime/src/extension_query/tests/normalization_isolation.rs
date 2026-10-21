use super::super::*;
use super::fixtures::*;

// Break caught: removing (kind,id) uniqueness, without an expectation/digest masking it.
#[test]
fn duplicate_pair_rejects_before_expectation() {
    let valid = document(&format!("{MCP},{REMOTE}"));
    let records = storage_header::parse(valid.as_bytes())
        .unwrap()
        .normalize()
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].key(), key(ExtensionKind::Mcp, "local-tools"));
    let duplicate = document(&format!("{MCP},{MCP}"));
    assert!(matches!(
        storage_header::parse(duplicate.as_bytes())
            .unwrap()
            .normalize(),
        Err(MetadataQueryError::InvalidSnapshot)
    ));
}

// Break caught: admitting '/' in a registration ID (not just a changed digest).
#[test]
fn slash_id_rejects_before_expectation() {
    let valid = document(MCP);
    let records = storage_header::parse(valid.as_bytes())
        .unwrap()
        .normalize()
        .unwrap();
    assert_eq!(records[0].key(), key(ExtensionKind::Mcp, "local-tools"));
    let invalid = valid.replace("local-tools", "bad/id");
    assert!(matches!(
        storage_header::parse(invalid.as_bytes())
            .unwrap()
            .normalize(),
        Err(MetadataQueryError::InvalidSnapshot)
    ));
}

// Break caught: dropping the strict core SemVer leading-zero rule.
#[test]
fn leading_zero_semver_rejects_before_expectation() {
    let valid = document(PLUGIN);
    let records = storage_header::parse(valid.as_bytes())
        .unwrap()
        .normalize()
        .unwrap();
    assert!(matches!(
        &records[0],
        ConfiguredMetadata::Plugin { package, .. } if package.version.0 == "1.0.0"
    ));
    let invalid = valid.replace("1.0.0", "01.0.0");
    assert!(matches!(
        storage_header::parse(invalid.as_bytes())
            .unwrap()
            .normalize(),
        Err(MetadataQueryError::InvalidSnapshot)
    ));
}

// Independent oracle cross_kind_ascii_case input + literal SHA256, SPEC §6.
// Provenance: d31-digest-oracle-20261021-1941-a9e7c214; no runtime tmp dependency.
// Breaks caught: ID-only uniqueness/get lookup, case-insensitive or ID-first sorting.
#[test]
fn cross_kind_same_id_file_list_get() {
    let records = r#"{"kind":"plugin","id":"same","record_revision":4,"package":{"version":"2.0.1","digest":"3333333333333333333333333333333333333333333333333333333333333333"}},
{"kind":"mcp","id":"a","record_revision":3,"transport":"remote_brokered","required_profile":{"id":"P","revision":2}},
{"kind":"mcp","id":"same","record_revision":2,"transport":"local_contained","required_profile":{"id":"p","revision":1}},
{"kind":"mcp","id":"Z","record_revision":1,"transport":"local_contained","required_profile":{"id":"P","revision":1}},
{"kind":"plugin","id":"A","record_revision":5,"package":{"version":"0.1.0","digest":"4444444444444444444444444444444444444444444444444444444444444444"}}"#;
    let text = document(records)
        .replace("fixture-owner", "case-owner")
        .replace(
            "\"registration_revision\":7",
            "\"registration_revision\":11",
        );
    let mut e = expected();
    e.scope.principal = runne_api::ApiPrincipalId::new("case-owner").unwrap();
    e.version.registration_revision = 11;
    e.version.metadata_digest =
        hex::decode("a466173ade28e9886019e74ab2184577924e8b3eb652217abaf8383777ae286e")
            .unwrap()
            .try_into()
            .unwrap();
    let mut req = request();
    req.context.principal = e.scope.principal.clone();
    req.expected_snapshot = e.version.clone();
    let owner = ConfiguredExtensionRegistry::capture(file(text.as_bytes()), e.clone()).unwrap();
    let reply = owner.query(req.clone()).unwrap();
    assert_eq!(reply.scope, e.scope);
    assert_eq!(reply.snapshot, e.version);
    assert_eq!(
        reply.records.iter().map(|r| r.key()).collect::<Vec<_>>(),
        vec![
            key(ExtensionKind::Mcp, "Z"),
            key(ExtensionKind::Mcp, "a"),
            key(ExtensionKind::Mcp, "same"),
            key(ExtensionKind::Plugin, "A"),
            key(ExtensionKind::Plugin, "same"),
        ]
    );
    for (kind, index) in [(ExtensionKind::Mcp, 2), (ExtensionKind::Plugin, 4)] {
        req.query = Query::Get {
            key: key(kind, "same"),
        };
        let got = owner.query(req.clone()).unwrap();
        assert_eq!(got.scope, reply.scope);
        assert_eq!(got.snapshot, reply.snapshot);
        assert_eq!(got.records, vec![reply.records[index].clone()]);
    }
}
