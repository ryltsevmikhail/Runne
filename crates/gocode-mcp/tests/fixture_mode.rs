use gocode_mcp::{FixtureMcpFailure, FixtureMcpMode, FixtureProfile, PRODUCTION_MCP_SDK_ENABLED};

const _: () = assert!(!PRODUCTION_MCP_SDK_ENABLED);

#[test]
fn fixture_mode_is_explicit_and_all_other_modes_fail_closed() {
    assert_eq!(FixtureMcpMode::FixtureOnly.label(), "FIXTURE_ONLY");
    assert_eq!(FixtureProfile::disabled().label(), "DISABLED_BY_POLICY");
    assert_eq!(FixtureProfile::not_activated().label(), "NOT_ACTIVATED");
    assert_eq!(
        FixtureMcpMode::ExternalEndpoint.activate(),
        Err(FixtureMcpFailure::ExternalEndpointUnsupported)
    );
    assert_eq!(
        FixtureMcpMode::LocalProcess.activate(),
        Err(FixtureMcpFailure::LocalProcessUnsupported)
    );
    assert_eq!(
        FixtureMcpMode::Production.activate(),
        Err(FixtureMcpFailure::ProductionSdkDisabled)
    );
}
