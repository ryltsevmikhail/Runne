use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use runne_api::ProviderReadinessStatusV1;
use runne_platform_desktop::ProtectedBundledRuntimeSupervisor;
use runne_runtime_client::AuthenticatedRuntimeClient;

const LABEL: &str = "com.runne.credential-service";
const SELECTOR: &str = "credential_service_real_process_pair_status_and_restart";

pub(super) fn run() {
    super::harness::dispatch_scenarios(SELECTOR, &["service-joined"], |context, _| {
        context.run_positive_transcript()
    });
}

pub(super) async fn prove_restart_rejoin(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    client: &AuthenticatedRuntimeClient,
    runtime: &Path,
) -> Result<(), &'static str> {
    let target = service_target()?;
    let old_pid = service_pid(&target)?.ok_or("service-pid-before-kill")?;
    let killed = Command::new("/bin/launchctl")
        .args(["kill", "SIGKILL", &target])
        .status()
        .map_err(|_| "service-kill-command")?;
    if !killed.success() {
        return Err("service-kill-status");
    }
    wait_for_service_exit(&target, old_pid)?;

    super::point_of_use::prove_service_loss_is_fenced(client, runtime).await?;
    complete_pending_rejoin(supervisor).await?;
    let renewed = supervisor
        .renew_profile()
        .map_err(|_| "service-rejoin-renew")?
        .connect(Duration::from_secs(10))
        .await
        .map_err(|_| "service-rejoin-connect")?;
    super::support::require_selected(&renewed, ProviderReadinessStatusV1::Ready)?;
    supervisor
        .record_client_ready(&renewed)
        .map_err(|_| "service-rejoin-ready")?;
    let new_pid = service_pid(&target)?.ok_or("service-pid-after-rejoin")?;
    (new_pid != old_pid)
        .then_some(())
        .ok_or("service-process-not-replaced")
}

pub(super) async fn complete_pending_rejoin(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
) -> Result<(), &'static str> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            return Err("service-rejoin-timeout");
        }
        if let Some(prepared) = supervisor
            .prepare_pending_credential_service_rejoin()
            .map_err(|_| "service-rejoin-prepare")?
        {
            let registered = prepared
                .register()
                .await
                .map_err(|_| "service-rejoin-register")?;
            supervisor
                .confirm_credential_service_rejoin(registered)
                .map_err(|_| "service-rejoin-confirm")?;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub(super) struct TemporaryCredentialService {
    domain: String,
    registered: bool,
}

impl TemporaryCredentialService {
    pub(super) fn bootstrap(
        root: &Path,
        home: &Path,
        keychain: &Path,
        executable: &Path,
    ) -> Result<Self, &'static str> {
        for path in [root, home, keychain, executable] {
            if !path.is_absolute() || !path.exists() {
                return Err("service-fixture-path");
            }
        }
        let uid = command_output("/usr/bin/id", &["-u"]).ok_or("service-uid")?;
        let domain = format!("gui/{}", uid.trim());
        let service = format!("{domain}/{LABEL}");
        let existing = Command::new("/bin/launchctl")
            .args(["print", &service])
            .output()
            .map_err(|_| "service-presence-command")?;
        if existing.status.success() || !not_found(&existing.stderr) {
            return Err("service-label-not-exclusively-available");
        }
        let plist = root.join("credential-service.test.plist");
        fs::write(&plist, launch_agent_plist(home, keychain, executable, root))
            .map_err(|_| "service-plist-write")?;
        fs::set_permissions(&plist, fs::Permissions::from_mode(0o600))
            .map_err(|_| "service-plist-mode")?;
        let status = Command::new("/bin/launchctl")
            .args(["bootstrap", &domain])
            .arg(&plist)
            .status()
            .map_err(|_| "service-bootstrap-command")?;
        if !status.success() {
            return Err("service-bootstrap-status");
        }
        Ok(Self {
            domain,
            registered: true,
        })
    }

    pub(super) fn shutdown(&mut self) -> Result<(), &'static str> {
        if !self.registered {
            return Ok(());
        }
        let service = format!("{}/{LABEL}", self.domain);
        let status = Command::new("/bin/launchctl")
            .args(["bootout", &service])
            .status()
            .map_err(|_| "service-bootout-command")?;
        if !status.success() {
            return Err("service-bootout-status");
        }
        self.registered = false;
        Ok(())
    }
}

impl Drop for TemporaryCredentialService {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
}

fn service_target() -> Result<String, &'static str> {
    let uid = command_output("/usr/bin/id", &["-u"]).ok_or("service-uid")?;
    Ok(format!("gui/{}/{LABEL}", uid.trim()))
}

fn service_pid(target: &str) -> Result<Option<u32>, &'static str> {
    let output = Command::new("/bin/launchctl")
        .args(["print", target])
        .output()
        .map_err(|_| "service-print-command")?;
    if !output.status.success() {
        return Err("service-print-status");
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "service-print-utf8")?;
    Ok(text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("pid = ")
            .and_then(|value| value.parse().ok())
    }))
}

fn wait_for_service_exit(target: &str, old_pid: u32) -> Result<(), &'static str> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if service_pid(target)? != Some(old_pid) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("service-kill-timeout")
}

fn not_found(stderr: &[u8]) -> bool {
    let value = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    value.contains("could not find service") || value.contains("service not found")
}

fn launch_agent_plist(home: &Path, keychain: &Path, executable: &Path, root: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\
         <key>Label</key><string>{LABEL}</string>\
         <key>ProgramArguments</key><array><string>{}</string></array>\
         <key>MachServices</key><dict>\
         <key>com.runne.credential-service.desktop.v1</key><true/>\
         <key>com.runne.credential-service.runtime.v1</key><true/>\
         <key>com.runne.credential-service.writer.v1</key><true/>\
         </dict><key>EnvironmentVariables</key><dict>\
         <key>HOME</key><string>{}</string>\
         <key>RUNNE_CI_MACOS_KEYCHAIN</key><string>{}</string>\
         <key>RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST</key><string>1</string>\
         <key>RUNNE_SLICE_E_FIXTURE_ROOT</key><string>{}</string>\
         <key>RUNNE_SLICE_E_SCENARIO</key><string>service-joined</string>\
         </dict><key>StandardErrorPath</key><string>{}</string>\
         <key>StandardOutPath</key><string>{}</string>\
         <key>ProcessType</key><string>Interactive</string>\
         <key>RunAtLoad</key><false/><key>KeepAlive</key><false/>\
         </dict></plist>\n",
        xml(executable),
        xml(home),
        xml(keychain),
        xml(root),
        xml(&root.join("credential-service.stderr")),
        xml(&root.join("credential-service.stdout")),
    )
}

fn xml(path: &Path) -> String {
    path.as_os_str()
        .to_string_lossy()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
