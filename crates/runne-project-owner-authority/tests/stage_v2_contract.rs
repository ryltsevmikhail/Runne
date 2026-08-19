use runne_project_owner_authority::{AuthorityError, STAGE_ENVELOPE_SCHEMA_V2};

#[test]
fn v2_is_the_only_stage_envelope_schema_for_v5_authority() {
    assert_eq!(
        STAGE_ENVELOPE_SCHEMA_V2,
        "runne.release.post-rc0-stage-envelope/2"
    );
    assert_eq!(
        AuthorityError::AuthorityVersionSuperseded.to_string(),
        "AUTHORITY_VERSION_SUPERSEDED"
    );
}
