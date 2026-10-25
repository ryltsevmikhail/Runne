#[test]
fn truncation_unknown_tags_trailing_and_domain_hash_fail_closed() {
    let binding = base();
    let (capture, digest, row) = packet(&binding);
    let context = from_capture(&binding, &capture, digest).unwrap();
    let bytes = wire::encode(&context).unwrap();
    let hash = wire::context_digest(&bytes).unwrap();
    for end in 1..bytes.len() {
        let shortened = &bytes[..end];
        let hash = wire::context_digest(shortened).unwrap();
        assert!(
            wire::decode_checked(shortened, &hash, &capture, &digest, &row).is_err(),
            "truncation {end}"
        );
    }
    for offset in [0usize, 2, 85, 86, 87] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        let hash = wire::context_digest(&bad).unwrap();
        assert!(
            wire::decode_checked(&bad, &hash, &capture, &digest, &row).is_err(),
            "unknown tag {offset}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    let new_hash = wire::context_digest(&trailing).unwrap();
    assert!(wire::decode_checked(&trailing, &new_hash, &capture, &digest, &row).is_err());
    assert!(wire::decode_checked(&bytes, &[0; 32], &capture, &digest, &row).is_err());
    assert!(wire::decode_checked(&bytes, &hash, &capture, &[0; 32], &row).is_err());
    assert!(wire::context_digest(&[]).is_err());
    assert!(wire::context_digest(&vec![1; 1048577]).is_err());
}

#[test]
fn rehashed_original_fact_tampering_cannot_replace_existing_binding_hashes() {
    let binding = base();
    let (capture, digest, row) = packet(&binding);
    let original = from_capture(&binding, &capture, digest).unwrap();
    for field in 0..8 {
        let mut changed = original.clone();
        match field {
            0 => changed.scope.lifetime_ms += 1,
            1 => changed.closed_snapshot.record.revision += 1,
            2 => changed.approval.expires_at_unix_ms += 1,
            3 => changed.approval.relevant_policy_digest = IntegrityDigest::from_bytes([0; 32]),
            4 => changed.canonical_binding_digest = [1; 32],
            5 => changed.capture_digest = [1; 32],
            6 => {
                changed.semantic_projection =
                    super::retained_context::OriginalSemanticProjectionV1::UnsupportedV1
            }
            _ => {
                changed.closed_snapshot.policy = changed
                    .closed_snapshot
                    .policy
                    .with_decision(ManagedEffectClass::ProcessStart, ManagedEffectDecision::Ask)
            }
        }
        let bytes = wire::encode(&changed).unwrap();
        let hash = wire::context_digest(&bytes).unwrap();
        assert!(
            wire::decode_checked(&bytes, &hash, &capture, &digest, &row).is_err(),
            "field {field}"
        );
    }
    for field in 0..9 {
        let mut changed = row.clone();
        match field {
            0 => changed.taskrun_id = [3; 16],
            1 => changed.attempt_id = [3; 16],
            2 => changed.invocation_id = [3; 16],
            3 => changed.fence += 1,
            4 => changed.binding_digest = [3; 32],
            5 => changed.native_owner_id = [3; 16],
            6 => changed.native_owner_generation = 1,
            7 => changed.selection_managed_policy_version += 1,
            _ => changed.selection_managed_policy_digest = [3; 32],
        }
        let bytes = wire::encode(&original).unwrap();
        let hash = wire::context_digest(&bytes).unwrap();
        assert!(
            wire::decode_checked(&bytes, &hash, &capture, &digest, &changed).is_err(),
            "row field {field}"
        );
    }
}

#[test]
fn legacy_absence_partial_pairs_and_expired_original_evidence_are_distinct() {
    let original = base();
    let binding = rebuild(
        &original,
        original.scope().clone(),
        original.closed_rules_snapshot(),
        PermissionMode::AskAlways,
        1,
        [0; 32],
    );
    let (capture, digest, row) = packet(&binding);
    let context = roundtrip(&binding);
    assert_eq!(context.approval.expires_at_unix_ms, 1);
    let bytes = wire::encode(&context).unwrap();
    let hash = wire::context_digest(&bytes).unwrap();
    assert_eq!(
        validate_optional_context_pair(None, None, &capture, &digest, &row).unwrap(),
        None
    );
    assert!(validate_optional_context_pair(Some(&bytes), None, &capture, &digest, &row).is_err());
    assert!(validate_optional_context_pair(None, Some(&hash), &capture, &digest, &row).is_err());
    assert!(
        validate_optional_context_pair(Some(&bytes), Some(&hash[..31]), &capture, &digest, &row)
            .is_err()
    );
    assert_eq!(
        validate_optional_context_pair(Some(&bytes), Some(&hash), &capture, &digest, &row).unwrap(),
        Some(context)
    );
}
