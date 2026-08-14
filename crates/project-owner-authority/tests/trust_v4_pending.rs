use gocode_project_owner_authority::{AuthorityError, v4_trust_schema_digests};

#[test]
fn v4_pins_remain_fail_closed_until_successor_leaf_schemas_are_finalized() {
    assert_eq!(
        v4_trust_schema_digests(),
        Err(AuthorityError::TrustV4PinsNotFinalized)
    );
}
