#[test]
fn bounded_root_framing_lengths_counts_and_paths_refuse_typed_data() {
    use ContextErrorV1::{InvalidOriginalData, MalformedWire};
    let original = base();
    let binding = bounded_binding(&original);
    let fixture = WireFixture::new(&binding);
    // Component sequence is a path, not a sorted set: z/a is canonical.
    let decoded = roundtrip(&binding);
    assert_eq!(decoded.scope, *binding.scope());
    for count in [0, 65, 255] {
        fixture.refuse(
            "root_count",
            "outside 1..64",
            &fixture.replace("root_count", &[count]),
            MalformedWire,
        );
    }
    for count in [257u16, u16::MAX] {
        let mut root = vec![9; 32];
        root.extend(count.to_be_bytes());
        fixture.refuse(
            "component_count",
            "over256 before component reads",
            &fixture.replace("roots", &root),
            MalformedWire,
        );
    }
    for length in [0u16, 256, u16::MAX] {
        let mut root = vec![9; 32];
        root.extend(1u16.to_be_bytes());
        root.extend(length.to_be_bytes());
        fixture.refuse(
            "component_length",
            "outside1..255 before payload read",
            &fixture.replace("roots", &root),
            MalformedWire,
        );
    }
    let root_start = fixture.fields["roots"].start;
    for (name, end) in [
        ("identity", root_start + 31),
        ("count", root_start + 33),
        ("length", root_start + 35),
        ("payload", root_start + 36),
    ] {
        fixture.refuse(
            name,
            "short bounded-root field with rehashed packet",
            &fixture.bytes[..end],
            MalformedWire,
        );
    }
    let mut missing_roots = fixture.bytes[..root_start].to_vec();
    missing_roots[fixture.fields["root_count"].start] = 64;
    fixture.refuse(
        "root_count64",
        "allowed count but missing first identity",
        &missing_roots,
        MalformedWire,
    );
    let mut missing_components = fixture.bytes[..root_start].to_vec();
    missing_components.extend([9; 32]);
    missing_components.extend(256u16.to_be_bytes());
    fixture.refuse(
        "component_count256",
        "allowed count but missing lengths",
        &missing_components,
        MalformedWire,
    );
    let long = raw_root(9, &vec![vec![b'a'; 255]; 17]);
    fixture.refuse(
        "joined_path",
        "4351 bytes exceeds4096",
        &fixture.replace("roots", &long),
        MalformedWire,
    );
    for part in [vec![0xff], vec![0xc3, 0x28]] {
        fixture.refuse(
            "component_utf8",
            "invalid UTF8",
            &fixture.replace("roots", &raw_root(9, &[part])),
            MalformedWire,
        );
    }
    for part in [".", "..", "a/b", "a\\b", "a\0b", "\u{85}", "\n"] {
        fixture.refuse(
            "component_path",
            "existing constructor excludes dot/separator/control",
            &fixture.replace("roots", &raw_root(9, &[part.as_bytes().to_vec()])),
            InvalidOriginalData,
        );
    }
    fixture.refuse(
        "root_identity",
        "zero held identity",
        &fixture.replace("roots", &raw_root(0, &[])),
        InvalidOriginalData,
    );
    let mut trailing = fixture.bytes.clone();
    trailing.push(0);
    fixture.refuse(
        "trailing",
        "bounded packet has no extensions",
        &trailing,
        MalformedWire,
    );
}

#[test]
fn bounded_root_entry_order_duplicates_and_overlap_are_not_component_sorting() {
    use ContextErrorV1::{InvalidOriginalData, MalformedWire};
    let original = base();
    let fixture = WireFixture::new(&bounded_binding(&original));
    for (name, roots, expected) in [
        (
            "duplicate",
            [raw_root(9, &[b"a".to_vec()]), raw_root(9, &[b"a".to_vec()])],
            MalformedWire,
        ),
        (
            "identity_order",
            [raw_root(10, &[]), raw_root(9, &[])],
            MalformedWire,
        ),
        (
            "path_entry_order",
            [raw_root(9, &[b"z".to_vec()]), raw_root(9, &[b"a".to_vec()])],
            MalformedWire,
        ),
        (
            "overlap",
            [
                raw_root(9, &[b"a".to_vec()]),
                raw_root(9, &[b"a".to_vec(), b"b".to_vec()]),
            ],
            InvalidOriginalData,
        ),
    ] {
        let bytes = fixture.replace("roots", &roots.concat());
        let mut bytes = bytes;
        bytes[fixture.fields["root_count"].start] = 2;
        fixture.refuse(
            name,
            "strict root Ord and nonoverlap before set normalization",
            &bytes,
            expected,
        );
    }
}
