#[test]
fn reserved_scope_tags_and_projection_payloads_refuse_even_when_rehashed() {
    use ContextErrorV1::{
        CorrelationMismatch, InvalidOriginalData, MalformedWire, UnsupportedWireVersion,
    };
    let original = base();
    let bounded = WireFixture::new(&bounded_binding(&original));
    let broad = WireFixture::new(&original);
    for fixture in [&bounded, &broad] {
        for (field, value, why) in [
            ("network", 1, "reserved Brokered"),
            ("coverage", 1, "nonclosed unrestricted"),
            ("coverage", 2, "nonclosed restricted"),
            ("rights_count", 5, "at most four rights"),
            ("children", 3, "unknown children"),
        ] {
            fixture.refuse(field, why, &fixture.replace(field, &[value]), MalformedWire);
        }
        for (field, value, expected) in [
            ("projection_version", vec![0, 2], UnsupportedWireVersion),
            ("projection_tag", vec![2], MalformedWire),
            ("policy_decisions", vec![0; 6], MalformedWire),
            ("lifetime", vec![0; 8], InvalidOriginalData),
            ("protected", vec![0; 32], InvalidOriginalData),
            ("epoch", vec![0; 8], InvalidOriginalData),
            ("mask", vec![255; 4], InvalidOriginalData),
        ] {
            fixture.refuse(
                field,
                "invalid frozen field domain",
                &fixture.replace(field, &value),
                expected,
            );
        }
    }
    for rights in [[1, 1, 3, 4], [2, 1, 3, 4], [1, 2, 3, 5]] {
        bounded.refuse(
            "rights",
            "duplicate/out-of-order/unknown right before set collection",
            &bounded.replace("rights", &rights),
            MalformedWire,
        );
    }
    let mut well_formed = broad.bytes.clone();
    well_formed[broad.fields["provided"].start] = 0;
    well_formed[broad.fields["decisions"].start] = 0;
    broad.refuse(
        "projection_flags",
        "well-formed presence pair still differs from derived original",
        &well_formed,
        CorrelationMismatch,
    );
    bounded.refuse(
        "unsupported_reason",
        "only frozen reason1",
        &bounded.replace("unsupported_reason", &[0]),
        MalformedWire,
    );
    bounded.refuse(
        "containment",
        "V2 cannot have bounded FS",
        &bounded.replace("containment", &[3]),
        InvalidOriginalData,
    );
    let mut budget = vec![1];
    budget.extend(0u64.to_be_bytes());
    broad.refuse(
        "operations",
        "broad numeric quota forbidden includingSome0",
        &broad.replace("operations", &budget),
        InvalidOriginalData,
    );
    for field in ["provided", "decisions", "semantics_digest"] {
        let mut payload = broad.bytes[broad.fields[field].clone()].to_vec();
        match field {
            "provided" => payload[0] = 2,
            "decisions" => payload[0] = 4,
            _ => payload[0] ^= 1,
        }
        broad.refuse(
            field,
            "invalid bool/decision or recomputed projection digest mismatch",
            &broad.replace(field, &payload),
            if field == "semantics_digest" {
                CorrelationMismatch
            } else {
                MalformedWire
            },
        );
    }
    for (field, index, value) in [("provided", 0, 0), ("decisions", 0, 0), ("decisions", 5, 1)] {
        let mut payload = broad.bytes[broad.fields[field].clone()].to_vec();
        assert_ne!(
            payload[index], value,
            "presence mutation must change its named field"
        );
        payload[index] = value;
        broad.refuse(
            field,
            "provided bit must equal decision presence",
            &broad.replace(field, &payload),
            MalformedWire,
        );
    }
    let mut changed = broad.bytes.clone();
    changed.truncate(broad.fields["projection_tag"].start);
    changed.extend([0, 1]);
    broad.refuse(
        "projection",
        "Unsupported cannot replace supported original",
        &changed,
        CorrelationMismatch,
    );
    let supported = &broad.bytes[broad.fields["projection_tag"].start..];
    let mut changed = bounded.bytes[..bounded.fields["projection_tag"].start].to_vec();
    changed.extend(supported);
    bounded.refuse(
        "projection",
        "Supported cannot replace unsupported original",
        &changed,
        CorrelationMismatch,
    );
}

#[test]
fn refreshed_capture_hash_does_not_mask_project_target_limits_or_selection_changes() {
    let original = base();
    let fixture = WireFixture::new(&original);
    let record = codec::decode(&fixture.capture).unwrap();
    for field in [
        "project_id",
        "target_identity",
        "target_version",
        "stdout_limit",
        "max_runtime_ms",
        "selection_expiry",
    ] {
        let mut changed = record.clone();
        match field {
            "project_id" => changed.project_id = [6; 16],
            "target_identity" => changed.target_identity[0] ^= 1,
            "target_version" => changed.target_version += 1,
            "stdout_limit" => changed.stdout_limit = 0,
            "max_runtime_ms" => changed.max_runtime_ms += 1,
            _ => changed.selection_expires_at = Some(1),
        }
        let capture = codec::encode(&changed).unwrap();
        let digest = codec::binding_digest(&capture).unwrap();
        let bytes = fixture.replace("capture_digest", &digest);
        let hash = wire::context_digest(&bytes).unwrap();
        let mut row = fixture.row.clone();
        row.binding_digest = digest;
        assert_eq!(
            wire::decode_checked(&bytes, &hash, &capture, &digest, &row),
            Err(ContextErrorV1::CorrelationMismatch),
            "{field}: original scope/approval/canonical binding must still correlate"
        );
    }
}
