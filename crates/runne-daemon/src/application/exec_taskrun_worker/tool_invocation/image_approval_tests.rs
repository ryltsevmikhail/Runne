use super::*;
#[test]
fn command_approval_binds_exact_gated_helper_image() {
    let digest = |image: Option<&[u8; 32]>| {
        approval_digest(
            TaskRunId::from_bytes([1; 16]),
            AttemptId::from_bytes([2; 16]),
            runne_domain::id::CycleId::from_bytes([3; 16]),
            0,
            8,
            "call",
            "workspace.command.run",
            "1",
            "linux-coding-agent-v1",
            "alice",
            &[4; 32],
            b"argv",
            None,
            &[5; 32],
            1,
            1,
            1,
            1,
            100,
            image,
        )
    };
    assert_ne!(digest(Some(&[6; 32])), digest(Some(&[7; 32])));
    assert_ne!(digest(Some(&[6; 32])), digest(None));
    assert_eq!(digest(Some(&[6; 32])), digest(Some(&[6; 32])));
}
