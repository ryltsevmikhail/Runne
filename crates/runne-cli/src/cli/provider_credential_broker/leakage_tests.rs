use std::io::{Cursor, Read};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use runne_provider::{CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialOperationAction};
use sha2::{Digest as _, Sha256};

use super::effect::execute_pair_effect;
use super::effect_test_support::{command, panicking_pair_claimed_with_ticket};

const TICKET_CANARY: &[u8; 32] = b"raw-ticket-canary-0123456789abcd";
const SEALED_PAYLOAD_CANARY: &[u8] = b"sealed-credential-canary-abcdefgh";
const CHILD_ENV: &str = "RUNNE_TEST_BROKER_CANARY_CHILD";

#[test]
fn provider_credential_broker_real_pair_path_redacts_live_canaries() {
    if let Some(mode) = std::env::var_os(CHILD_ENV) {
        run_live_canary_child(mode == "released");
        return;
    }
    let blocked = run_canary_child_process("withheld");
    assert!(!blocked.status.success());
    assert!(!String::from_utf8_lossy(&blocked.stderr).contains("controlled writer panic"));
    let child = run_canary_child_process("released");
    assert!(!child.status.success());
    let child_stdout = String::from_utf8(child.stdout).expect("child stdout");
    let child_stderr = String::from_utf8(child.stderr).expect("child stderr");
    assert!(child_stderr.contains("controlled writer panic"));
    let outcome = super::broker_process_outcome(Err(super::CliError::CredentialOperation));
    let ticket_digest = hex::encode(Sha256::digest(TICKET_CANARY));
    let credential_digest = hex::encode(Sha256::digest(SEALED_PAYLOAD_CANARY));
    let canaries = [
        std::str::from_utf8(TICKET_CANARY).expect("ticket canary"),
        std::str::from_utf8(SEALED_PAYLOAD_CANARY).expect("credential canary"),
        ticket_digest.as_str(),
        credential_digest.as_str(),
    ];

    let surfaces: [(&str, String); 4] = [
        ("child stdout", child_stdout),
        ("panic stderr", child_stderr),
        ("stdout", outcome.stdout),
        ("stderr", outcome.stderr),
    ];
    for (surface, output) in surfaces {
        for canary in canaries {
            assert!(!output.contains(canary), "{surface} disclosed {canary}");
        }
    }
}

fn run_canary_child_process(mode: &str) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("leakage_tests::provider_credential_broker_real_pair_path_redacts_live_canaries")
        .arg("--nocapture")
        .env(CHILD_ENV, mode)
        .output()
        .expect("isolated canary child")
}

fn run_live_canary_child(released: bool) {
    let fixture = panicking_pair_claimed_with_ticket(*TICKET_CANARY, released);
    let secret_reached = Arc::new(AtomicBool::new(false));
    let mut secret = TrackingReader {
        input: Cursor::new(encoded_pair_envelope(&live_canary_payload())),
        reached: secret_reached.clone(),
    };
    let authority = fixture
        .claimed
        .read_pair_secret(&mut secret)
        .expect("sealed secret reader");

    assert!(secret_reached.load(Ordering::SeqCst));
    let control = fixture.written.lock().expect("control output").clone();
    assert!(
        control
            .windows(TICKET_CANARY.len())
            .any(|bytes| bytes == TICKET_CANARY)
    );
    assert!(matches!(
        CredentialBrokerFrameCodec::read_from(&mut Cursor::new(control)),
        Ok(CredentialBrokerFrame::Claim {
            secret_offer: Some(_),
            ..
        })
    ));
    let _ = execute_pair_effect(authority);
    panic!("writer did not invoke the controlled panic")
}

fn live_canary_payload() -> Vec<u8> {
    let ticket_digest = hex::encode(Sha256::digest(TICKET_CANARY));
    let credential_digest = hex::encode(Sha256::digest(SEALED_PAYLOAD_CANARY));
    [
        SEALED_PAYLOAD_CANARY,
        ticket_digest.as_bytes(),
        credential_digest.as_bytes(),
    ]
    .concat()
}

struct TrackingReader {
    input: Cursor<Vec<u8>>,
    reached: Arc<AtomicBool>,
}

impl Read for TrackingReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.reached.store(true, Ordering::SeqCst);
        self.input.read(bytes)
    }
}

fn encoded_pair_envelope(payload: &[u8]) -> Vec<u8> {
    let command = command(CredentialOperationAction::Pair);
    let plaintext_len = u16::try_from(payload.len()).expect("payload length");
    let mut bytes = vec![0; 124 + usize::from(plaintext_len) + 16];
    bytes[..2].copy_from_slice(&[
        runne_provider::CredentialSecretEnvelopeCodec::VERSION,
        2,
    ]);
    bytes[2..18].copy_from_slice(&command.operation_id().as_bytes());
    bytes[18..26].copy_from_slice(&command.ticket_attempt().get().to_be_bytes());
    bytes[26..58].fill(13);
    bytes[58..90].fill(14);
    bytes[90..122].fill(15);
    bytes[122..124].copy_from_slice(&plaintext_len.to_be_bytes());
    bytes[124..124 + payload.len()].copy_from_slice(payload);
    bytes[124 + payload.len()..].fill(16);
    bytes
}
