use std::process::Command;

use sha2::{Digest as _, Sha256};

const BROKER_MODE: &str = "__provider-credential-broker-v1";

#[test]
fn provider_credential_broker_redacts_argv_and_environment_canaries() {
    let ticket = "raw-ticket-canary-7c7966fdb00e4ca9";
    let credential = "credential-canary-sk-live-24b6e6cfc116";
    let ticket_digest = hex::encode(Sha256::digest(ticket.as_bytes()));
    let credential_digest = hex::encode(Sha256::digest(credential.as_bytes()));
    let canaries = [ticket, credential, &ticket_digest, &credential_digest];
    let output = Command::new(env!("CARGO_BIN_EXE_runne"))
        .arg(BROKER_MODE)
        .args(canaries.iter().copied())
        .env("RUNNE_TEST_RAW_TICKET", ticket)
        .env("RUNNE_TEST_CREDENTIAL", credential)
        .env("RUNNE_TEST_TICKET_DIGEST", &ticket_digest)
        .env("RUNNE_TEST_CREDENTIAL_DIGEST", &credential_digest)
        .output()
        .expect("run closed broker invocation");

    assert!(!output.status.success());
    for (surface, bytes) in [
        ("stdout", output.stdout.as_slice()),
        ("stderr/panic/log", output.stderr.as_slice()),
    ] {
        let output = String::from_utf8_lossy(bytes);
        for canary in canaries {
            assert!(!output.contains(canary), "{surface} disclosed {canary}");
        }
    }
}
