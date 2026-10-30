#[test]
fn selection_expiry_options_remain_independent_of_original_approval_expiry() {
    let original = base();
    for selection_expiry in [None, Some(1), Some(43), Some(i64::MAX)] {
        for approval_expiry in [1, 42, i64::MAX] {
            let mut selection = original.selection().clone();
            selection.expires_at_unix_ms = selection_expiry;
            let binding = rebuild_selected(
                &original,
                original.scope().clone(),
                original.closed_rules_snapshot(),
                selection,
                approval_expiry,
                [0; 32],
            );
            let decoded = roundtrip(&binding);
            assert_eq!(decoded.selection.expires_at_unix_ms, selection_expiry);
            assert_eq!(decoded.approval.expires_at_unix_ms, approval_expiry);
        }
    }
    // Zero selection expiry is not accepted by the existing checked domain.
    let fixture = WireFixture::new(&original);
    let mut record = codec::decode(&fixture.capture).unwrap();
    record.selection_expires_at = Some(0);
    let capture = codec::encode(&record).unwrap();
    let digest = codec::binding_digest(&capture).unwrap();
    let bytes = fixture.replace("capture_digest", &digest);
    let hash = wire::context_digest(&bytes).unwrap();
    let mut row = fixture.row.clone();
    row.binding_digest = digest;
    assert_eq!(
        wire::decode_checked(&bytes, &hash, &capture, &digest, &row),
        Err(ContextErrorV1::InvalidOriginalData)
    );
}
