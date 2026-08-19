fn valid_next(expected: Option<&SecurityAnchorV1>, next: &SecurityAnchorV1) -> bool {
    expected.map_or_else(
        || next.generation == 1 && next.previous_anchor_digest == [0; 32],
        |previous| {
            next.profile_identity_digest == previous.profile_identity_digest
                && next.database_identity == previous.database_identity
                && previous.generation.checked_add(1) == Some(next.generation)
                && next.previous_anchor_digest == previous.digest()
        },
    )
}

fn test_tag(
    profile: [u8; 32],
    database_identity: [u8; 32],
    generation: u64,
    transaction_digest: [u8; 32],
    previous_anchor_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"test-only/runne/security-seal/v1\0");
    hasher.update(profile);
    hasher.update(database_identity);
    hasher.update(generation.to_be_bytes());
    hasher.update(transaction_digest);
    hasher.update(previous_anchor_digest);
    hasher.finalize().into()
}
