fn id(value: &str) -> BoundedCanonicalId {
    BoundedCanonicalId::parse(canonical_id(value).as_bytes()).expect("canonical id")
}

fn canonical_id(value: &str) -> String {
    if value.len() == 36 {
        return value.to_owned();
    }
    let hash = value.bytes().fold(0_u64, |hash, byte| {
        hash.wrapping_mul(16_777_619).wrapping_add(u64::from(byte))
    });
    format!(
        "018f2e3a-7000-7000-8000-{:012x}",
        hash & 0x0000_ffff_ffff_ffff
    )
}

fn identity(
    key: &str,
    operation: MutationOperation,
    target: MutationTargetKind,
    target_id: &str,
    version: u64,
) -> MutationIdentity {
    MutationIdentity::new(
        [1; 32],
        [2; 32],
        operation,
        target,
        id(target_id),
        key,
        version,
        [3; 32],
    )
    .unwrap()
}
