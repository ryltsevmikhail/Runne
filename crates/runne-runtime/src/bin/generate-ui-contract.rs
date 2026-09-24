use std::env;
use std::path::PathBuf;

use runne_runtime::contract_generation::{
    check_ui_contract, check_ui_contract_v3, generate_ui_contract, generate_ui_contract_v3,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("generate-ui-contract: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let mut output = None;
    let mut check = false;
    let mut profile = 2_u8;
    while let Some(argument) = arguments.next() {
        if argument == "--check" {
            check = true;
        } else if argument == "--output" {
            output = Some(PathBuf::from(
                arguments.next().ok_or("--output requires a path")?,
            ));
        } else if argument == "--profile" {
            profile = arguments
                .next()
                .ok_or("--profile requires 2 or 3")?
                .to_string_lossy()
                .parse()?;
            if profile != 2 && profile != 3 {
                return Err("--profile requires 2 or 3".into());
            }
        } else {
            return Err(format!("unknown argument: {}", argument.to_string_lossy()).into());
        }
    }

    let target = output.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(format!("contracts/gocode-ui-client-{profile}"))
    });
    match (profile, check) {
        (2, true) => check_ui_contract(&target)?,
        (2, false) => generate_ui_contract(&target)?,
        (3, true) => check_ui_contract_v3(&target)?,
        (3, false) => generate_ui_contract_v3(&target)?,
        _ => unreachable!("profile was validated"),
    }
    Ok(())
}
