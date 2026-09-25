use std::io::{BufRead as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use runne_provider::{CredentialMaterial, CredentialServiceProtocolCodec};
use zeroize::Zeroizing;

const CHILD_TEST: &str = "secret_lifetime_tests::process_canary::child_entry";
const SCENARIO_ENV: &str = "RUNNE_SECRET_CANARY_SCENARIO";
const EVIDENCE_ENV: &str = "RUNNE_SECRET_CANARY_EVIDENCE";
static NEXT_PATH: AtomicUsize = AtomicUsize::new(1);

#[test]
fn subprocess_canary_outputs_and_artifacts_stay_closed() {
    let canary = Zeroizing::new(
        format!(
            "runne-process-canary-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        )
        .into_bytes(),
    );
    for scenario in [
        "success",
        "validation_failure",
        "malformed_frame",
        "cancellation",
    ] {
        let evidence = run_scenario(scenario, &canary);
        assert_closed(scenario, &evidence, &canary);
    }
    let evidence = run_terminated_scenario(&canary);
    assert_closed("process_termination", &evidence, &canary);
}

fn run_scenario(scenario: &str, canary: &[u8]) -> Vec<u8> {
    let evidence_path = evidence_path(scenario);
    let mut child = spawn_child(scenario, &evidence_path);
    write_stdin(&mut child, canary);
    let output = child.wait_with_output().expect("wait for canary child");
    assert!(output.status.success(), "{scenario}: child failed");
    collect_evidence(output.stdout, &output.stderr, &evidence_path)
}

fn run_terminated_scenario(canary: &[u8]) -> Vec<u8> {
    let scenario = "process_termination";
    let evidence_path = evidence_path(scenario);
    let mut child = spawn_child(scenario, &evidence_path);
    write_stdin(&mut child, canary);
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = std::io::BufReader::new(stdout);
    let mut captured = Vec::new();
    loop {
        let mut line = Vec::new();
        let count = stdout
            .read_until(b'\n', &mut line)
            .expect("child ready line");
        assert_ne!(count, 0, "child exited before ready event");
        let ready = line.ends_with(b"process-canary-ready\n");
        captured.extend_from_slice(&line);
        if ready {
            break;
        }
    }
    child.kill().expect("terminate canary child");
    let status = child.wait().expect("wait for terminated child");
    assert!(
        !status.success(),
        "termination scenario must end by process death"
    );
    let mut remaining = Vec::new();
    stdout
        .read_to_end(&mut remaining)
        .expect("remaining stdout");
    captured.extend_from_slice(&remaining);
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_end(&mut stderr)
        .expect("stderr");
    collect_evidence(captured, &stderr, &evidence_path)
}

fn spawn_child(scenario: &str, evidence_path: &Path) -> std::process::Child {
    Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--ignored",
            "--exact",
            CHILD_TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(SCENARIO_ENV, scenario)
        .env(EVIDENCE_ENV, evidence_path)
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn canary child")
}

fn write_stdin(child: &mut std::process::Child, canary: &[u8]) {
    let mut stdin = child.stdin.take().expect("child stdin");
    stdin
        .write_all(canary)
        .expect("write canary only through stdin");
    drop(stdin);
}

fn collect_evidence(mut stdout: Vec<u8>, stderr: &[u8], path: &Path) -> Vec<u8> {
    stdout.extend_from_slice(stderr);
    let artifact = std::fs::read(path).expect("closed evidence artifact");
    stdout.extend_from_slice(&artifact);
    std::fs::remove_file(path).expect("remove disposable evidence artifact");
    stdout
}

fn assert_closed(scenario: &str, evidence: &[u8], canary: &[u8]) {
    assert!(
        !evidence
            .windows(canary.len())
            .any(|window| window == canary),
        "{scenario} leaked the stdin canary"
    );
    let text = std::str::from_utf8(evidence).expect("closed evidence is UTF-8");
    assert!(text.contains(&format!("\"scenario\":\"{scenario}\"")));
    assert!(text.contains("\"evidenceClass\":\"supporting_leak_surface\""));
    assert!(text.contains("\"arbitraryMemoryZeroizationProof\":false"));
    let expected_drop_events = usize::from(scenario != "process_termination");
    assert!(text.contains(&format!("\"dropEvents\":{expected_drop_events}")));
}

fn evidence_path(scenario: &str) -> PathBuf {
    let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "runne-d1-1c-{}-{}-{sequence}.json",
        std::process::id(),
        scenario
    ))
}

struct WitnessedSecret {
    bytes: Option<Zeroizing<Vec<u8>>>,
    material: Option<CredentialMaterial>,
    drops: Arc<AtomicUsize>,
}

impl WitnessedSecret {
    fn new(bytes: Zeroizing<Vec<u8>>, drops: Arc<AtomicUsize>) -> Self {
        Self {
            bytes: Some(bytes),
            material: None,
            drops,
        }
    }

    fn take_bytes(&mut self) -> Zeroizing<Vec<u8>> {
        self.bytes.take().expect("secret bytes owned")
    }

    fn retain_material(&mut self, material: CredentialMaterial) {
        self.material = Some(material);
    }
}

impl Drop for WitnessedSecret {
    fn drop(&mut self) {
        drop(self.material.take());
        drop(self.bytes.take());
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
#[ignore = "invoked only as the subprocess side of the parent canary test"]
fn child_entry() {
    let scenario = std::env::var(SCENARIO_ENV).expect("child scenario");
    let evidence_path = PathBuf::from(std::env::var_os(EVIDENCE_ENV).expect("evidence path"));
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take((CredentialMaterial::MAX_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .expect("read secret from stdin");
    assert!(!input.is_empty() && input.len() <= CredentialMaterial::MAX_BYTES);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut secret = WitnessedSecret::new(input, Arc::clone(&drops));
    let outcome = exercise_scenario(&scenario, &mut secret);
    if scenario == "process_termination" {
        write_artifact(&evidence_path, &scenario, outcome, 0);
        println!("process-canary-ready");
        std::io::stdout().flush().expect("flush ready event");
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    drop(secret);
    write_artifact(
        &evidence_path,
        &scenario,
        outcome,
        drops.load(Ordering::Acquire),
    );
}

fn exercise_scenario(scenario: &str, secret: &mut WitnessedSecret) -> &'static str {
    match scenario {
        "success" | "process_termination" => {
            let material = CredentialMaterial::from_zeroizing(secret.take_bytes())
                .expect("bounded canary material");
            secret.retain_material(material);
            if scenario == "success" {
                "completed"
            } else {
                "ready_for_termination"
            }
        }
        "validation_failure" => {
            let mut bytes = secret.take_bytes();
            bytes.resize(CredentialMaterial::MAX_BYTES + 1, 0);
            assert!(CredentialMaterial::from_zeroizing(bytes).is_err());
            "rejected"
        }
        "malformed_frame" => {
            let error = CredentialServiceProtocolCodec::decode_writer_request(
                secret.bytes.as_deref().expect("secret bytes owned"),
            )
            .err()
            .expect("canary is not a service frame");
            assert_eq!(format!("{error:?}"), "InvalidFrame");
            "invalid_frame"
        }
        "cancellation" => "cancelled_before_effect",
        _ => panic!("unknown closed canary scenario"),
    }
}

fn write_artifact(path: &Path, scenario: &str, outcome: &str, drop_events: usize) {
    let artifact = format!(
        "{{\"schemaVersion\":1,\"scenario\":\"{scenario}\",\"outcome\":\"{outcome}\",\"dropEvents\":{drop_events},\"evidenceClass\":\"supporting_leak_surface\",\"arbitraryMemoryZeroizationProof\":false}}\n"
    );
    std::fs::write(path, artifact).expect("write closed canary evidence");
}
