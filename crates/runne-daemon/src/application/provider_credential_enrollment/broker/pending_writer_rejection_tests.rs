use super::*;

#[test]
fn awaiting_writer_rejects_expiry_and_full_binding_changes() {
    for changed in [
        "expired",
        "session",
        "release",
        "peer",
        "daemon",
        "database",
        "supervisor",
    ] {
        let fixture = binding_fixture(4_000_000_000);
        let (sealed, sender_authenticator) = transfer_authority(&fixture.issuer, [18; 32], [4; 32]);
        let channel = [19; 32];
        let (awaiting, publication_key) = awaiting(&fixture, channel, sealed);
        let release_tuple = fixture.release_tuple;
        let candidate = match changed {
            "session" => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [20; 32],
                1,
                [6; 32],
                1,
                [5; 32],
            ),
            "release" => fixture
                .issuer
                .issue_base([3; 32], [21; 32], [4; 32], 1, [6; 32], 1, [5; 32]),
            "peer" => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [4; 32],
                1,
                [6; 32],
                1,
                [22; 32],
            ),
            "daemon" => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [4; 32],
                1,
                [23; 32],
                1,
                [5; 32],
            ),
            "database" => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [4; 32],
                1,
                [6; 32],
                2,
                [5; 32],
            ),
            "supervisor" => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [4; 32],
                2,
                [6; 32],
                1,
                [5; 32],
            ),
            _ => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [4; 32],
                1,
                [6; 32],
                1,
                [5; 32],
            ),
        }
        .unwrap();
        let now = if changed == "expired" {
            4_000_000_000
        } else {
            100
        };
        let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        let sender_thread = std::thread::spawn(move || {
            send_evidence(
                sender,
                &sender_authenticator,
                release_tuple,
                channel,
                publication_key,
            )
        });

        assert!(
            awaiting
                .receive_writer_evidence(
                    receiver,
                    &fixture.operation,
                    &candidate,
                    &fixture.proof,
                    now,
                )
                .is_err()
        );
        assert!(sender_thread.join().unwrap().is_err());
    }
}
