// ── Public helpers ───────────────────────────────────────────────────────────

/// Public re-export for testing: build a `HighWaterRef`.
pub fn build_test_high_water_ref(
    authority_id: &[u8; 16],
    floor: Option<i64>,
    global_position: i64,
    server_secret: &[u8; 32],
    session_id: &[u8; 16],
) -> Vec<u8> {
    build_high_water_ref(
        authority_id,
        floor,
        global_position,
        server_secret,
        session_id,
    )
}
