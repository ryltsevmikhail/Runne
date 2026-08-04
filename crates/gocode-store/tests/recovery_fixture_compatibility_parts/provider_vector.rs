use fixture_readers::validate_provider_prepared;

#[test]
fn synthetic_provider_prepared_v1_vector_uses_exact_framing() {
    let (_directory, path, entry) = copied_fixture("provider-prepared-v1-vector.sqlite");
    assert_eq!(entry.fixture_kind, recovery_fixtures::FixtureKind::SyntheticTestVector);
    assert_eq!(entry.integrity_profile, 1);
    assert_eq!(entry.digest_domain, "ProviderPreparedV1");
    let rows = validate_provider_prepared(&path).unwrap();
    assert_eq!(rows.len(), entry.expected_rows.len());
    for (actual, expected) in rows.iter().zip(&entry.expected_rows) {
        assert_eq!(expected.table, "provider_prepared_requests");
        assert_eq!(actual.get("call_id"), Some(&expected.primary_key_hex));
        assert_eq!(actual, &expected.columns);
    }
}
