use super::*;

pub(super) fn matches_with(
    connection: &Connection,
    insert_trigger: &str,
    head_trigger: &str,
    extensions: &CredentialSchemaExtensions<'_>,
) -> SqliteResult<bool> {
    let additional = V27_TRIGGERS
        .map(|name| (name, v27_trigger_source(name)))
        .into_iter()
        .chain(V28_TRIGGERS.map(|name| (name, v28_trigger_source(name))))
        .chain(V29_TRIGGERS.map(|name| (name, v29_trigger_source(name))))
        .chain(V30_TRIGGERS.map(|name| (name, source(name))))
        .chain(extensions.triggers.iter().copied())
        .map(|(name, source)| {
            (
                name,
                extensions
                    .replacements
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map_or(source, |(_, replacement)| *replacement),
            )
        })
        .collect::<Vec<_>>();
    let mut replacements = vec![
        (
            "provider_credential_operation_insert_prepared",
            insert_trigger,
        ),
        ("provider_credential_head_active_lifecycle", head_trigger),
    ];
    replacements.extend_from_slice(extensions.replacements);
    v26_trigger_catalog::matches_with_replacements(connection, &additional, &replacements)
}

pub(super) fn source(name: &str) -> &'static str {
    let start = MIGRATION_V30
        .find(&format!("CREATE TRIGGER {name}"))
        .expect("V30 trigger exists");
    let end = MIGRATION_V30[start..]
        .find("END;")
        .expect("V30 trigger ends")
        + start
        + 4;
    &MIGRATION_V30[start..end]
}
