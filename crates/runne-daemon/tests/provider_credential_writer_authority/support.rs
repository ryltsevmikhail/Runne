use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use runne_api::{
    BeginProviderCredentialEnrollment, ProviderActivationBindingV1,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2, ProviderReadinessStatusV1,
};
use runne_platform_desktop::{
    ConfirmedInstalledNativeEnrollment, CredentialWriterHandoffMode,
    DevelopmentBundledRuntimeLauncher, NativeProtectedCredentialEnrollmentBegin,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeSupervisor,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const FIXTURE_ROOT: &str = "RUNNE_SLICE_E_FIXTURE_ROOT";

pub(super) struct InnerContext {
    root: PathBuf,
    profile: PathBuf,
    runtime: PathBuf,
    daemon: PathBuf,
}

impl InnerContext {
    pub(super) fn from_environment() -> Result<Self, &'static str> {
        let root = PathBuf::from(std::env::var_os(FIXTURE_ROOT).ok_or("fixture-root-env")?);
        let root = fs::canonicalize(root).map_err(|_| "fixture-root-canonical")?;
        let current = fs::canonicalize(std::env::current_exe().map_err(|_| "current-desktop")?)
            .map_err(|_| "current-desktop-canonical")?;
        if current != root.join("Runne.app/Contents/MacOS/runne-desktop") {
            return Err("desktop-package-identity");
        }
        let profile = root.join("profile");
        let runtime = profile.join("runtime");
        fs::create_dir_all(&runtime).map_err(|_| "runtime-directory")?;
        for directory in [&profile, &runtime] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| "runtime-directory-mode")?;
        }
        Ok(Self {
            daemon: root.join("Runne.app/Contents/MacOS/runned"),
            root,
            profile,
            runtime,
        })
    }
    pub(super) fn run_positive_transcript(&self, admission_only: bool) -> Result<(), &'static str> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "tokio-runtime")?;
        runtime.block_on(self.positive_async(admission_only))
    }
    pub(super) fn root(&self) -> &Path {
        &self.root
    }
    pub(super) fn profile(&self) -> &Path {
        &self.profile
    }
    pub(super) fn runtime_root(&self) -> &Path {
        &self.runtime
    }
    pub(super) fn daemon(&self) -> &Path {
        &self.daemon
    }
    pub(super) fn writer(&self) -> PathBuf {
        self.root.join("Runne.app/Contents/MacOS/runne")
    }
    pub(super) fn supervisor(
        &self,
    ) -> Result<super::scoped_cleanup::ScopedSupervisor, &'static str> {
        let spec = ProtectedBundledRuntimeLaunchSpec::new(&self.daemon, &self.runtime)
            .map_err(|_| "launch-spec")?
            .with_provider_activation(ProviderActivationBindingV1::openai_responses_text_v1());
        Ok(super::scoped_cleanup::ScopedSupervisor::new(
            ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec),
        ))
    }

    async fn positive_async(&self, admission_only: bool) -> Result<(), &'static str> {
        let prepared = runne_platform_desktop::prepare_local_native_enrollment(&self.profile)
            .ok_or("local-admission")?;
        let mut supervisor = self.supervisor()?;
        supervisor.start().map_err(|_| "initial-runned-start")?;
        let initial = connect(&mut supervisor, "initial").await?;
        require_selected(&initial, ProviderReadinessStatusV1::CredentialMissing)?;
        supervisor
            .record_client_ready(&initial)
            .map_err(|_| "initial-ready")?;
        drop(initial);
        let confirmed = supervisor
            .confirm_installed_native_enrollment(prepared)
            .map_err(|_| "local-confirmation")?;
        supervisor
            .begin_credential_enrollment_transition(&confirmed)
            .map_err(|_| "v3-transition")?;
        let v3 = connect(&mut supervisor, "v3").await?;
        supervisor
            .record_client_ready(&v3)
            .map_err(|_| "v3-ready")?;
        drop(v3);
        register_credential_service_session(&mut supervisor, &confirmed).await?;
        let secret = Zeroizing::new(super::audit::secret_canary(&self.root));
        let command_id = uuid::Uuid::now_v7().to_string();
        let command = BeginProviderCredentialEnrollment::new(
            ProviderCredentialEnrollmentActionV2::Pair,
            ProviderCredentialProviderV2::OpenAi,
            1,
            &command_id,
            format!("slice-e-{command_id}"),
            "slice-e-native-intent",
        )
        .map_err(|_| "begin-command")?;
        let begin = NativeProtectedCredentialEnrollmentBegin::new(
            command,
            super::audit::ticket_canary(secret.as_slice()),
        )
        .map_err(|_| "native-begin")?;
        let mut enrollment = supervisor
            .begin_protected_credential_enrollment(begin)
            .map_err(|_| "protected-begin")?;
        if enrollment.snapshot().state() != ProviderCredentialOperationStateV2::Prepared {
            return Err("prepared-state");
        }
        let mut handoff = supervisor
            .run_credential_writer_handoff(&confirmed, CredentialWriterHandoffMode::Pair)
            .inspect_err(|error| {
                use runne_platform_desktop::ProtectedBundledRuntimeError as Error;
                let category = match error {
                    Error::OwnershipMismatch => "ownership",
                    Error::InvalidState => "state",
                    Error::ProtectedChannelUnavailable => "channel",
                    Error::ReadinessTimeout => "readiness",
                    Error::SpawnFailed => "spawn",
                    Error::ExecutableIdentityMismatch => "identity",
                    _ => "other-closed-category",
                };
                eprintln!("writer-handoff-category={category}");
            })
            .map_err(|_| "writer-handoff")?;
        supervisor
            .receive_credential_secret_relay(&mut enrollment)
            .map_err(|_| "secret-relay")?;
        let relay = enrollment.take_relay().ok_or("relay-take")?;
        if admission_only {
            drop(handoff.take_pair_secret_relay());
            supervisor
                .crash_local_fixture_process()
                .map_err(|_| "admission-daemon-crash")?;
            supervisor.stop().map_err(|_| "admission-stop")?;
            handoff
                .reap_exact_writer_bounded(Duration::from_secs(10))
                .map_err(|_| "admission-reap")?;
            super::native_item::assert_absent(&self.root)?;
            return super::release_fault_support::assert_no_owned_children(self);
        }
        let audit_secret = secret.clone();
        let secret_digest = hex::encode(Sha256::digest(secret.as_slice()));
        if runne_api::test_support::local_native_enrollment_case()
            == Some(runne_api::test_support::LocalNativeEnrollmentCase::Leakage)
        {
            let patterns = super::audit::sensitive_patterns(secret.as_slice());
            super::audit::assert_live_children_clean(&self.root, &patterns)?;
        }
        handoff
            .take_pair_secret_relay()
            .ok_or("pair-relay")?
            .seal_and_write(&relay, secret)
            .map_err(|_| "sealed-fd3")?;
        supervisor
            .finish_protected_credential_enrollment(&mut enrollment, &relay)
            .map_err(|_| "terminal-readback")?;
        if !enrollment.terminal()
            || enrollment.snapshot().state() != ProviderCredentialOperationStateV2::Completed
        {
            return Err("terminal-state");
        }
        handoff.reap_exact_writer().map_err(|_| "writer-reap")?;
        let current = supervisor
            .renew_profile()
            .map_err(|_| "status-renewal")?
            .connect(Duration::from_secs(10))
            .await
            .map_err(|_| "status-connect")?;
        require_selected(&current, ProviderReadinessStatusV1::Ready)?;
        if service_fixture_enabled() {
            super::point_of_use::prove(&current, &self.runtime).await?;
        }
        supervisor
            .record_client_ready(&current)
            .map_err(|_| "status-ready")?;
        if service_fixture_enabled() {
            super::service_process::prove_restart_rejoin(&mut supervisor, &current, &self.runtime)
                .await?;
        }
        drop(current);
        supervisor.stop().map_err(|_| "first-runned-stop")?;
        assert_durable_counts(&self.runtime)?;
        supervisor.start().map_err(|_| "restart-runned")?;
        let restarted = connect(&mut supervisor, "restart").await?;
        require_selected(&restarted, ProviderReadinessStatusV1::Ready)?;
        supervisor
            .record_client_ready(&restarted)
            .map_err(|_| "restart-ready")?;
        drop(restarted);
        supervisor.stop().map_err(|_| "restart-stop")?;
        assert_durable_counts(&self.runtime)?;
        let environment = std::env::vars_os()
            .flat_map(|(key, value)| [key, value])
            .collect::<Vec<_>>();
        if environment.iter().any(|value| {
            value
                .as_encoded_bytes()
                .windows(audit_secret.len())
                .any(|part| part == audit_secret.as_slice())
        }) {
            return Err("secret-environment");
        }
        if super::audit::tree_contains(
            &self.root,
            &[audit_secret.as_slice(), secret_digest.as_bytes()],
        )? {
            return Err("secret-persistent-sink");
        }
        Ok(())
    }
}

fn service_fixture_enabled() -> bool {
    runne_api::test_support::local_credential_service_fixture_enabled()
}

pub(super) async fn register_credential_service_session(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    confirmed: &ConfirmedInstalledNativeEnrollment,
) -> Result<(), &'static str> {
    if !service_fixture_enabled() {
        return Ok(());
    }
    let prepared = supervisor
        .prepare_credential_service_session_registration(confirmed)
        .map_err(|_| "service-registration-prepare")?;
    let registered = prepared
        .register()
        .await
        .map_err(|_| "service-registration-exchange")?;
    supervisor
        .confirm_credential_service_session(registered)
        .map_err(|_| "service-registration-confirm")
}

pub(super) async fn connect(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    stage: &'static str,
) -> Result<runne_runtime_client::AuthenticatedRuntimeClient, &'static str> {
    supervisor
        .take_runtime_profile()
        .ok_or("runtime-profile")?
        .connect(Duration::from_secs(10))
        .await
        .map_err(|_| stage)
}

pub(super) fn require_selected(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    expected: ProviderReadinessStatusV1,
) -> Result<(), &'static str> {
    client
        .provider_statuses()
        .iter()
        .find(|status| status.selected())
        .filter(|status| status.readiness() == expected)
        .map(|_| ())
        .ok_or("provider-readiness")
}

pub(super) fn assert_durable_counts(runtime: &Path) -> Result<(), &'static str> {
    let database = runtime.join("runne-daemon/event-log.db");
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| "sqlite-open")?;
    for (table, expected) in [
        ("provider_credential_operations", 1_i64),
        ("provider_credential_ticket_attempts", 1),
        ("provider_credential_completion_receipts", 1),
        ("provider_credential_readiness_observations", 1),
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .map_err(|_| "sqlite-count")?;
        if count != expected {
            return Err("sqlite-cardinality");
        }
    }
    let state: String = connection
        .query_row(
            "SELECT state FROM provider_credential_operations",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "sqlite-state")?;
    (state == "COMPLETED")
        .then_some(())
        .ok_or("sqlite-terminal")
}
