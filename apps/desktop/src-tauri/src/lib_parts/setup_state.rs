fn directory_managers() -> (
    DirectorySelectionManager,
    crate::prepared_workspace::PreparedWorkspaceManager,
) {
    let selections = DirectorySelectionManager::new(std::time::Duration::from_secs(30))
        .expect("fixed directory selection lifetime is valid");
    let prepared = selections.prepared_workspaces();
    (selections, prepared)
}

fn credential_intent_registry() -> crate::provider_credential_enrollment::CredentialIntentRegistry {
    crate::provider_credential_enrollment::CredentialIntentRegistry::new(
        std::time::Duration::from_secs(30),
    )
    .expect("fixed credential intent lifetime is valid")
}
