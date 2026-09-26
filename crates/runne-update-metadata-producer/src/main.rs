use std::path::Path;

#[cfg(all(
    target_os = "macos",
    feature = "dev-loopback-updater",
    debug_assertions
))]
mod demo;

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let result = match arguments.as_slice() {
        #[cfg(all(target_os = "linux", debug_assertions, feature = "dev-keyset-init"))]
        [_, command, manifest_flag, path, store_flag, store]
            if command == "init-dev-keyset"
                && manifest_flag == "--public-manifest"
                && store_flag == "--key-store"
                && store == "secret-service" =>
        {
            runne_update_metadata_producer::initialize_linux_dev_keyset(Path::new(path))
        }
        #[cfg(target_os = "linux")]
        [
            _,
            command,
            draft_flag,
            draft,
            output_flag,
            output,
            store_flag,
            store,
        ] if command == "issue"
            && draft_flag == "--draft"
            && output_flag == "--output"
            && store_flag == "--key-store"
            && store == "secret-service" =>
        {
            runne_update_metadata_producer::issue_from_files_secret_service(
                Path::new(draft),
                Path::new(output),
            )
        }
        [_, command, manifest_flag, path, keychain_flag, keychain]
            if command == "init-dev-keyset"
                && manifest_flag == "--public-manifest"
                && keychain_flag == "--keychain-ref" =>
        {
            runne_update_metadata_producer::initialize_dev_keyset(
                Path::new(path),
                Path::new(keychain),
            )
        }
        [
            _,
            command,
            draft_flag,
            draft,
            output_flag,
            output,
            keychain_flag,
            keychain,
        ] if command == "issue"
            && draft_flag == "--draft"
            && output_flag == "--output"
            && keychain_flag == "--keychain-ref" =>
        {
            runne_update_metadata_producer::issue_from_files(
                Path::new(draft),
                Path::new(output),
                Path::new(keychain),
            )
        }
        #[cfg(all(
            target_os = "macos",
            feature = "dev-loopback-updater",
            debug_assertions
        ))]
        [_, command, config_flag, config] if command == "demo" && config_flag == "--config" => {
            demo::run(Path::new(config))
        }
        _ => Err(runne_update_metadata_producer::ProducerError::Input),
    };
    match result {
        Ok(()) => println!("{{\"status\":\"complete\"}}"),
        Err(error) => {
            eprintln!("{{\"status\":\"failed\",\"reason\":\"{error}\"}}");
            std::process::exit(1);
        }
    }
}
