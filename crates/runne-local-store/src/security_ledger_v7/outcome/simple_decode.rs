fn project(input: &mut &[u8], tag: u8) -> Result<CanonicalMutationOutcome, SecurityStateError> {
    let id = codec::id(input)?;
    let new_version = version(input)?;
    Ok(match tag {
        1 => CanonicalMutationOutcome::ProjectCreate {
            project_id: id,
            new_version,
        },
        11 => CanonicalMutationOutcome::ProjectRename {
            project_id: id,
            new_version,
        },
        2 => CanonicalMutationOutcome::ProjectArchive {
            project_id: id,
            new_version,
        },
        _ => CanonicalMutationOutcome::ProjectDelete {
            project_id: id,
            new_version,
        },
    })
}
fn workspace(input: &mut &[u8], tag: u8) -> Result<CanonicalMutationOutcome, SecurityStateError> {
    let id = codec::id(input)?;
    let new_version = version(input)?;
    Ok(match tag {
        4 => CanonicalMutationOutcome::WorkspaceCreate {
            workspace_id: id,
            new_version,
        },
        5 => CanonicalMutationOutcome::WorkspaceBindRoot {
            workspace_id: id,
            new_version,
        },
        _ => CanonicalMutationOutcome::WorkspaceOpen {
            workspace_id: id,
            new_version,
        },
    })
}
