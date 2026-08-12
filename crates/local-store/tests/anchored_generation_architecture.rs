#[test]
fn replay_generation_writes_are_fenced_behind_the_anchored_transition() {
    for source in [
        include_str!("../src/replay_apply.rs"),
        include_str!("../src/replay_access.rs"),
    ] {
        assert!(
            source.find("AnchoredAdmissionRequired") < source.find("UPDATE meta SET db_generation"),
            "offline replay code must reject an anchored database before generation mutation"
        );
    }
    assert!(include_str!("../src/replay_anchored.rs").contains("commit_anchored_security_write"));
}
