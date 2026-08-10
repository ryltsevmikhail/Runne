use gocode_domain::id::ProjectId;

#[test]
fn project_workspace_project_id_roundtrips_a_valid_uuid_v7() {
    let project_id = ProjectId::parse("018f47a2-4f8c-7b52-8c35-7a3a14c2d9e1").unwrap();

    assert_eq!(
        ProjectId::parse(&project_id.to_string()).unwrap(),
        project_id
    );
}
