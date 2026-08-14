use std::collections::BTreeMap;
use std::process::Command;

use tempfile::tempdir;

pub fn command(arguments: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gocode"));
    command.args(arguments);
    command
}

pub fn assert_usage(arguments: &[&str]) {
    assert_eq!(
        command(arguments)
            .output()
            .expect("run command")
            .status
            .code(),
        Some(2)
    );
}

pub fn assert_plan(arguments: &[&str], operation: &str, keys: &[&str], _: &str) {
    let directory = tempdir().expect("temporary directory");
    let output = command(arguments)
        .current_dir(directory.path())
        .output()
        .expect("run command");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(
        directory
            .path()
            .read_dir()
            .expect("read directory")
            .next()
            .is_none()
    );
    let input_digests = arguments[4..]
        .chunks_exact(2)
        .map(|pair| {
            (
                pair[0].trim_start_matches("--").to_owned(),
                pair[1].to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(input_digests.len(), keys.len());
    let expected = serde_json::to_string(&serde_json::json!({
        "external_effects": [], "input_digests": input_digests,
        "operation": operation, "status": "BLOCKED(PROMOTION_AUTHORITY_NOT_PROVISIONED)",
    }))
    .expect("canonical JSON");
    assert_eq!(output.stdout, format!("{expected}\n").as_bytes());
}
