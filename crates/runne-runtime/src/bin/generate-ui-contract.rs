use std::env;
use std::path::PathBuf;

use runne_runtime::contract_generation::{check_ui_contract, generate_ui_contract};

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
    while let Some(argument) = arguments.next() {
        if argument == "--check" {
            check = true;
        } else if argument == "--output" {
            output = Some(PathBuf::from(
                arguments.next().ok_or("--output requires a path")?,
            ));
        } else {
            return Err(format!("unknown argument: {}", argument.to_string_lossy()).into());
        }
    }

    let target = output.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("contracts/gocode-ui-client-2")
    });
    if check {
        check_ui_contract(&target)?;
    } else {
        generate_ui_contract(&target)?;
    }
    Ok(())
}
