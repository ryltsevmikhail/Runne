use runne_local_store::{BoundedCanonicalId, CanonicalMutationOutcome, NormalizedMutationCommand};

#[test]
fn rename_roundtrips_and_correlates_only_exact_successor_version() {
    let id = BoundedCanonicalId::parse(b"01890e00-0000-7000-8000-000000000001").unwrap();
    let command = NormalizedMutationCommand::RenameProject {
        project_id: id.clone(),
        expected_version: 7,
        display_name: "New name".into(),
    };
    let bytes = command.encode().unwrap();
    assert_eq!(NormalizedMutationCommand::decode(&bytes).unwrap(), command);
    let outcome = CanonicalMutationOutcome::ProjectRename {
        project_id: id.clone(),
        new_version: 8,
    };
    assert_eq!(
        CanonicalMutationOutcome::decode(&outcome.encode().unwrap()).unwrap(),
        outcome
    );
    assert!(outcome.correlates_to_command(&command));
    for version in [7, 9] {
        assert!(
            !CanonicalMutationOutcome::ProjectRename {
                project_id: id.clone(),
                new_version: version
            }
            .correlates_to_command(&command)
        );
    }
    assert!(
        !CanonicalMutationOutcome::ProjectArchive {
            project_id: id.clone(),
            new_version: 8
        }
        .correlates_to_command(&command)
    );
    for name in ["", "\n", &"я".repeat(129)] {
        assert!(
            NormalizedMutationCommand::RenameProject {
                project_id: id.clone(),
                expected_version: 7,
                display_name: name.into()
            }
            .encode()
            .is_err()
        );
    }
}
