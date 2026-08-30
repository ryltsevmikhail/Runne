use std::path::Path;

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let result = match arguments.as_slice() {
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
