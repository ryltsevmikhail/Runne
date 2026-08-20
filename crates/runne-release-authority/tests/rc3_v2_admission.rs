use runne_release_authority::{AuthorityError, inspect_rc3_v2_leaf};

#[test]
fn rc3_v2_leafs_remain_fail_closed_and_legacy_is_superseded() {
    assert_eq!(
        inspect_rc3_v2_leaf(
            "gocode.release.rc3-publication-authorization/1",
            br#"{"schema_version":"gocode.release.rc3-publication-authorization/1"}\n"#,
        ),
        Err(AuthorityError::AuthorityVersionSuperseded)
    );
    let corpus: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../runne-promotion-contracts/tests/fixtures/rc3_v2_corpus.json"
    ))
    .unwrap();
    let mut payload = serde_json::to_vec(&corpus["publication_manifest"]).unwrap();
    payload.push(b'\n');
    assert_eq!(
        inspect_rc3_v2_leaf("gocode.release.publication-manifest/2", &payload),
        Err(AuthorityError::PolicyUnresolved)
    );
}

#[test]
fn same_version_runne_rc3_schema_is_not_an_alias() {
    let corpus: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../runne-promotion-contracts/tests/fixtures/rc3_v2_corpus.json"
    ))
    .unwrap();
    let mut payload = serde_json::to_vec(&corpus["publication_manifest"]).unwrap();
    let schema = b"gocode.release.publication-manifest/2";
    let offset = payload.windows(schema.len()).position(|window| window == schema).unwrap();
    payload.splice(
        offset..offset + schema.len(),
        b"runne.release.publication-manifest/2".iter().copied(),
    );
    payload.push(b'\n');

    assert_eq!(
        inspect_rc3_v2_leaf("runne.release.publication-manifest/2", &payload),
        Err(AuthorityError::BindingMismatch)
    );
}
