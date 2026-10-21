use super::super::*;
use super::fixtures::*;
use MetadataQueryError::*;
// Breaks caught: digest drift, bounds omission, raw Debug/source leakage, activation call.
#[test]
fn canonical_digest_matches_independent_vector() {
    let o = capture(&json()).unwrap();
    let r = o.query(request()).unwrap();
    assert_eq!(r.snapshot.metadata_digest, super::vectors::DIGEST);
    assert_eq!(
        hex::encode(super::super::digest::preimage(&r.scope, 7, &r.records)),
        super::vectors::PREIMAGE_HEX
    );
    // Independent oracle packet vector, no production encoder used for this expectation.
    let records = r#"{"kind":"plugin","id":"p","record_revision":9223372036854775807,"package":{"version":"4294967295.4294967295.4294967295","digest":"abababababababababababababababababababababababababababababababab"}},{"kind":"mcp","id":"m","record_revision":9223372036854775807,"transport":"remote_brokered","required_profile":{"id":"R","revision":9223372036854775807}}"#;
    let text = document(records)
        .replace("fixture-owner", &"я".repeat(128))
        .replace(
            "\"registration_revision\":7",
            "\"registration_revision\":9223372036854775807",
        );
    let mut e = expected();
    e.scope.principal = runne_api::ApiPrincipalId::new("я".repeat(128)).unwrap();
    e.scope.runtime_generation = i64::MAX as u64;
    e.version.registration_revision = i64::MAX as u64;
    e.version.metadata_digest =
        hex::decode("d033cb90e0592147d79fd2eb60c1686577faff5a587006745d6fb6747a06163e")
            .unwrap()
            .try_into()
            .unwrap();
    let mut req = request();
    req.context.principal = e.scope.principal.clone();
    req.context.runtime_generation = e.scope.runtime_generation;
    req.expected_snapshot = e.version.clone();
    let owner = ConfiguredExtensionRegistry::capture(file(text.as_bytes()), e).unwrap();
    assert_eq!(owner.query(req).unwrap().records.len(), 2);
    assert!(runne_api::ApiPrincipalId::new("я".repeat(129)).is_err());
}
#[test]
fn reordering_cannot_change_digest() {
    let a = capture(&json()).unwrap();
    let b = capture(&document(&format!(
        "{MCP},{REMOTE},{PLUGIN},{}",
        PLUGIN.replace("formatter", "linter")
    )))
    .unwrap();
    assert_eq!(
        a.query(request()).unwrap().records,
        b.query(request()).unwrap().records
    );
}
#[test]
fn byte_count_depth_and_reply_limits_reject() {
    let mut exact = json().into_bytes();
    exact.resize(1_048_576, b' ');
    assert!(ConfiguredExtensionRegistry::capture(file(&exact), expected()).is_ok());
    assert_eq!(
        ConfiguredExtensionRegistry::capture(file(&vec![b' '; 1_048_577]), expected()).unwrap_err(),
        LimitExceeded
    );
    let records = (0..257)
        .map(|i| MCP.replace("local-tools", &format!("id-{i}")))
        .collect::<Vec<_>>()
        .join(",");
    reject(&document(&records), LimitExceeded);
    assert_eq!(super::super::digest::reply_budget(131_008), Ok(()));
    assert_eq!(
        super::super::digest::reply_budget(131_009),
        Err(LimitExceeded)
    );
    assert_eq!(
        super::super::digest::reply_budget(usize::MAX),
        Err(LimitExceeded)
    );
}
#[test]
fn identities_versions_revisions_and_digests_are_closed() {
    assert_eq!(
        storage_header::parse(json().as_bytes())
            .unwrap()
            .normalize()
            .unwrap()
            .len(),
        4
    );
    for (from, to) in [
        ("local-tools", "bad/id"),
        ("sdk-required", ""),
        ("1.0.0", "01.0.0"),
        ("1.0.0", "1.0.0-alpha"),
        ("1.0.0", "4294967296.0.0"),
        ("\"record_revision\":2", "\"record_revision\":0"),
        (
            "\"registration_revision\":7",
            "\"registration_revision\":9223372036854775808",
        ),
        ("\"revision\":1", "\"revision\":0"),
        ("fixture-owner", ""),
        (AUTH, "00000000000000000000000000000000"),
        (PROJECT, "01800000000040008000000000000002"),
        ("local_contained", "unknown"),
        (
            "1111111111111111111111111111111111111111111111111111111111111111",
            "AA",
        ),
    ] {
        let text = json().replace(from, to);
        assert!(matches!(
            storage_header::parse(text.as_bytes()).and_then(|wire| wire.normalize()),
            Err(InvalidSnapshot)
        ));
        // Keep File coverage too; this assertion alone is not guard-isolated.
        reject(&text, InvalidSnapshot);
    }
    for replacement in ["a".repeat(129), "é".into()] {
        let text = json().replace("local-tools", &replacement);
        assert!(matches!(
            storage_header::parse(text.as_bytes()).and_then(|wire| wire.normalize()),
            Err(InvalidSnapshot)
        ));
        reject(&text, InvalidSnapshot);
    }
    let mut e = expected();
    e.scope.runtime_generation = 0;
    assert_eq!(
        ConfiguredExtensionRegistry::capture(file(json().as_bytes()), e).unwrap_err(),
        InvalidRequest
    );
    let mut e = expected();
    e.version.schema_version = 2;
    assert_eq!(
        ConfiguredExtensionRegistry::capture(file(json().as_bytes()), e).unwrap_err(),
        UnsupportedContract
    );
}
#[test]
fn disallowed_canaries_never_echo_in_debug_or_error() {
    for field in ["url", "env", "secret_ref", "description", "argv"] {
        let text = json().replacen('{', &format!("{{\"{field}\":\"synthetic-canary\","), 1);
        let err = capture(&text).unwrap_err();
        assert_eq!(err, InvalidSnapshot);
        assert!(!format!("{err:?}:{err}").contains("synthetic-canary"));
    }
}
#[test]
fn query_does_not_write_or_activate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    std::fs::write(&path, json()).unwrap();
    let o = ConfiguredExtensionRegistry::capture(std::fs::File::open(&path).unwrap(), expected())
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    let entries = std::fs::read_dir(dir.path()).unwrap().count();
    for _ in 0..4 {
        o.query(request()).unwrap();
        let mut r = request();
        r.context.runtime_generation = 2;
        assert_eq!(o.query(r).unwrap_err(), StaleGeneration);
    }
    o.close(1).unwrap();
    assert_eq!(o.query(request()).unwrap_err(), OwnerClosed);
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), entries);
}
#[test]
fn mcp_sdk_disabled_plugin_activation_unknown() {
    assert_eq!(
        super::super::record::mcp_availability(runne_mcp::PRODUCTION_MCP_SDK_ENABLED),
        Ok(McpAvailability::SdkProfileUnavailable)
    );
    assert_eq!(
        super::super::record::mcp_availability(true),
        Err(UnsupportedContract)
    );
    let r = capture(&json()).unwrap().query(request()).unwrap();
    for record in r.records {
        match record {
            ConfiguredMetadata::Mcp { availability, .. } => {
                assert_eq!(availability, McpAvailability::SdkProfileUnavailable)
            }
            ConfiguredMetadata::Plugin { availability, .. } => {
                assert_eq!(availability, PluginAvailability::ActivationNotIntegrated)
            }
        }
    }
}
#[test]
fn allowed_secret_shaped_id_remains_internal_data() {
    let text = json().replace("local-tools", "token-SYNTHETIC-secret");
    let e = expected_for(&text);
    let v = e.version.clone();
    let o = ConfiguredExtensionRegistry::capture(file(text.as_bytes()), e).unwrap();
    let mut req = request();
    req.expected_snapshot = v;
    let reply = o.query(req).unwrap();
    assert!(
        reply
            .records
            .iter()
            .any(|r| r.key().id.0 == "token-SYNTHETIC-secret")
    );
    assert!(!format!("{reply:?}").contains("SYNTHETIC"));
}
#[test]
fn reply_request_source_owner_debug_are_opaque() {
    let o = capture(&json()).unwrap();
    let r = o.query(request()).unwrap();
    let mut values = vec![
        format!(
            "{:?}",
            super::super::capture::Source(file(json().as_bytes()))
        ),
        format!("{o:?}"),
        format!("{:?}", request()),
        format!("{:?}", request().context),
        format!("{:?}", expected()),
        format!("{:?}", scope()),
        format!("{:?}", version()),
        format!("{r:?}"),
        format!("{:?}", key(ExtensionKind::Mcp, "secret")),
        format!("{:?}", RegistrationId("secret".into())),
        format!("{:?}", ProfileId("secret".into())),
        format!("{:?}", PackageVersion("1.0.0".into())),
    ];
    for record in r.records {
        values.push(format!("{record:?}"));
        match record {
            ConfiguredMetadata::Mcp {
                required_profile, ..
            } => values.push(format!("{required_profile:?}")),
            ConfiguredMetadata::Plugin { package, .. } => values.push(format!("{package:?}")),
        }
    }
    for value in values {
        assert!(value.ends_with("(<opaque>)"));
        for canary in ["fixture-owner", "local-tools", "111111", "1.0.0", "secret"] {
            assert!(!value.contains(canary));
        }
    }
}
#[test]
fn error_codes_do_not_echo_input_or_current_values() {
    for e in [
        InvalidRequest,
        UnsupportedContract,
        SourceUnavailable,
        InvalidSnapshot,
        ScopeDenied,
        StaleGeneration,
        StaleSnapshot,
        OwnerClosed,
        NotFound,
        LimitExceeded,
        InternalUnavailable,
    ] {
        let code = e.to_string();
        assert!(code.len() <= 64);
        assert!(code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        assert_eq!(format!("{e:?}"), code);
        assert!(std::error::Error::source(&e).is_none());
    }
}
#[test]
fn maximum_valid_snapshot_is_bounded_end_to_end() {
    let records = (0..256)
        .map(|i| {
            MCP.replace("local-tools", &format!("id-{i:03}{}", "x".repeat(122)))
                .replace("sdk-required", &"p".repeat(128))
                .replace("\"revision\":1", "\"revision\":9223372036854775807")
        })
        .collect::<Vec<_>>()
        .join(",");
    let text = document(&records);
    let e = expected_for(&text);
    let v = e.version.clone();
    let o = ConfiguredExtensionRegistry::capture(file(text.as_bytes()), e).unwrap();
    let mut r = request();
    r.expected_snapshot = v;
    assert_eq!(o.query(r).unwrap().records.len(), 256);
}
