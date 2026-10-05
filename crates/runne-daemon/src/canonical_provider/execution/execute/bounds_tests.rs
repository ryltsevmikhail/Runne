use super::bounded_tool_poll_exhausted;

#[test]
fn production_guard_is_tool_only_and_stops_before_poll_513() {
    let mut cursor = 0;
    let mut coordinator_polls = 0;
    while !bounded_tool_poll_exhausted(true, cursor, false) {
        coordinator_polls += 1;
        cursor += 1;
    }
    assert_eq!((coordinator_polls, cursor), (512, 512));
    assert!(bounded_tool_poll_exhausted(true, cursor, false));

    // Text mode runs the same shared `next_and_commit` coordinator without
    // inheriting the D2-only cap, including after cursor 512 and on deadline.
    assert!(!bounded_tool_poll_exhausted(false, 513, false));
    assert!(!bounded_tool_poll_exhausted(false, 10_000, true));
    assert!(!bounded_tool_poll_exhausted(true, 511, false));
    assert!(bounded_tool_poll_exhausted(true, 0, true));
}
