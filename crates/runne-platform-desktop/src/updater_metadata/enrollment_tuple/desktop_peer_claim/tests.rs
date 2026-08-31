use super::desktop_peer_digest;

#[test]
fn peer_claim_changes_for_every_authoritative_binding() {
    let base = desktop_peer_digest([1; 32], [2; 32], [3; 32], 4, [5; 16], [6; 16], 7);
    for changed in [
        desktop_peer_digest([8; 32], [2; 32], [3; 32], 4, [5; 16], [6; 16], 7),
        desktop_peer_digest([1; 32], [8; 32], [3; 32], 4, [5; 16], [6; 16], 7),
        desktop_peer_digest([1; 32], [2; 32], [8; 32], 4, [5; 16], [6; 16], 7),
        desktop_peer_digest([1; 32], [2; 32], [3; 32], 8, [5; 16], [6; 16], 7),
        desktop_peer_digest([1; 32], [2; 32], [3; 32], 4, [8; 16], [6; 16], 7),
        desktop_peer_digest([1; 32], [2; 32], [3; 32], 4, [5; 16], [8; 16], 7),
        desktop_peer_digest([1; 32], [2; 32], [3; 32], 4, [5; 16], [6; 16], 8),
    ] {
        assert_ne!(base, changed);
    }
}
