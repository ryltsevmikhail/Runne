//! Explicit offline native adoption command; never part of daemon startup.
use std::ffi::OsString;

pub fn run(arguments: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
    use runne_daemon::protected_activation::terminal_adoption;
    let preview = match arguments {
        [prepare] if prepare == "prepare" => terminal_adoption::prepare()?,
        [commit, manifest] if commit == "commit" => {
            let manifest = manifest.to_str().ok_or("invalid adoption manifest")?;
            if manifest.len() != 64 || !manifest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid adoption manifest".into());
            }
            terminal_adoption::commit(manifest)?
        }
        [repin, previous, manifest] if repin == "repin-tools" => {
            let manifest = manifest.to_str().ok_or("invalid adoption manifest")?;
            terminal_adoption::repin_tools(std::path::Path::new(previous), manifest)?
        }
        [upgrade, directory, previous, manifest] if upgrade == "upgrade-images" => {
            terminal_adoption::upgrade_images(
                std::path::Path::new(directory),
                std::path::Path::new(previous),
                manifest.to_str().ok_or("invalid upgrade manifest")?,
            )?
        }
        _ => return Err("usage: runned terminal-adoption prepare|commit MANIFEST".into()),
    };
    println!("{}", serde_json::to_string(&preview)?);
    Ok(())
}
