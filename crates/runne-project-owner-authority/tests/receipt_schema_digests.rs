use runne_project_owner_authority::{
    AuthorityError, SchemaDigest, v1_platform_scope_schema_digests,
};

mod receipt_support;

#[test]
fn receipt_requires_exact_pinned_receipt_and_decision_schema_digests() {
    let expected = v1_platform_scope_schema_digests();
    let mut independently_mutable = v1_platform_scope_schema_digests();
    independently_mutable[0].schema_id = "gocode.other/1".into();
    assert_eq!(expected, v1_platform_scope_schema_digests());
    assert_ne!(expected, independently_mutable);
    for digests in [
        vec![expected[0].clone()],
        vec![SchemaDigest {
            schema_id: "gocode.other/1".into(),
            schema_sha256: [0; 32],
        }],
        vec![
            expected[0].clone(),
            SchemaDigest {
                schema_id: expected[1].schema_id.clone(),
                schema_sha256: [0; 32],
            },
        ],
    ] {
        assert_eq!(
            receipt_support::signed_with_schema_digests(digests),
            Err(AuthorityError::InvalidSchemaDigests)
        );
    }
}
