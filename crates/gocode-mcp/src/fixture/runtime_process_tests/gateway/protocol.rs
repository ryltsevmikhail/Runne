use super::super::routing::support::protocol_fixture;

#[test]
fn protocol_dispatch_behavior_remains_available() {
    let (mut runtime, approval, mut capability) = protocol_fixture();
    assert!(runtime.dispatch(&mut capability, Some(&approval)).is_ok());
}
