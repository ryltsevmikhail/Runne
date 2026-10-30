//! Exact namespace continuation for the adopted CLI installation.
use super::*;

pub fn credential_access(
    connection: &runne_store::schema::ManagedConnection,
) -> Result<runne_secure_store::ProviderCredentialAccessPolicy, DaemonError> {
    let (config, images, root) = verified_target().map_err(target_error)?;
    let database: String = connection
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| failure("provider_compose_adopted_database"))?;
    if Path::new(&database) != Path::new(&config.db_path)
        || !adopted_connection(&config, &root, connection)
            .map_err(|_| failure("provider_compose_adopted_binding"))?
    {
        return Err(failure("provider_compose_adopted_owner"));
    }
    runne_platform_desktop::verify_terminal_installation_source(
        &root,
        &crate::config::external_config_path(),
    )
    .map_err(|_| failure("provider_compose_adopted_witness"))?;
    images
        .access()
        .map_err(|_| failure("provider_compose_adopted_access"))
}

fn target_error(error: DaemonError) -> DaemonError {
    let code = match &error {
        DaemonError::Config(_) => "provider_compose_adopted_config",
        DaemonError::Bootstrap(message) => match message.as_str() {
            "adoption requires the existing standalone DeepSeek text installation" => {
                "provider_compose_adopted_config_policy"
            }
            "adoption runtime layout unavailable"
            | "adoption root unavailable"
            | "adoption requires the existing protected-compatible path layout"
            | "adoption runtime root is not owner-private" => "provider_compose_adopted_layout",
            "host image unavailable"
            | "host directory unavailable"
            | "credential host image unavailable"
            | "installed host image unavailable"
            | "installed credential host unavailable"
            | "live host image unavailable" => "provider_compose_adopted_image_open",
            "credential host image is aliased" => "provider_compose_adopted_image_alias",
            "host directory is not owner controlled"
            | "credential host image is not owner controlled" => {
                "provider_compose_adopted_image_owner"
            }
            "CLI credential host is not enabled" | "credential host image pins do not match" => {
                "provider_compose_adopted_image_pins"
            }
            "running host image differs from installed image" => {
                "provider_compose_adopted_running_image"
            }
            "credential host configuration changed" => "provider_compose_adopted_config_changed",
            "credential host image changed"
            | "credential host image changed during measurement" => {
                "provider_compose_adopted_image_changed"
            }
            _ => "provider_compose_adopted_target",
        },
        _ => "provider_compose_adopted_target",
    };
    failure(code)
}
