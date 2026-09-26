fn linux_enrollment_approval_requested(
    arguments: &[OsString],
) -> Result<bool, Box<dyn std::error::Error>> {
    let flag = OsStr::new("--approve-linux-enrollment=catalog");
    let count = arguments
        .iter()
        .filter(|argument| argument.as_os_str() == flag)
        .count();
    if count > 1
        || arguments.iter().any(|argument| {
            argument
                .to_string_lossy()
                .starts_with("--approve-linux-enrollment=")
                && argument.as_os_str() != flag
        })
    {
        return Err("invalid enrollment approval option".into());
    }
    Ok(count == 1)
}

fn start_linux_enrollment_approval(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let result = approve_linux_catalog(&app).await;
        eprintln!(
            "linux-enrollment-approval:{}",
            if result.is_ok() {
                "published"
            } else {
                "failed"
            }
        );
        app.exit(i32::from(result.is_err()));
    });
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "retain signed updater and live runtime fences through atomic approval publication"
)]
async fn approve_linux_catalog(app: &tauri::AppHandle) -> Result<(), ()> {
    use runne_api::provider_credential_enrollment::linux_activation_policy::{
        LinuxEnrollmentActivationRecord, LinuxEnrollmentScope,
    };
    use runne_app_core::RuntimeAvailability;
    use tauri::Manager as _;

    let core = app.state::<Arc<AppCore>>().inner().clone();
    let lifecycle = app.state::<RuntimeLifecycleManager>();
    let live = lifecycle.connect_runtime(&core).await.map_err(|_| ())? == RuntimeAvailability::Live;
    if !live {
        return Err(());
    }
    let executable = std::env::current_exe().map_err(|_| ())?;
    let resources = app.path().resource_dir().map_err(|_| ())?;
    let mut installed = app
        .state::<crate::updater_status::UpdateStatusStore>()
        .prepare_linux_installed_native_enrollment(&executable, &resources)
        .await?
        .ok_or(())?;
    installed.refresh_linux()?;
    let runtime = lifecycle
        .acquire_credential_enrollment_lease()
        .await
        .map_err(|_| ())?;
    let confirmed = runtime
        .confirm(installed.take_prepared()?)
        .await
        .map_err(|_| ())?;
    installed.revalidate_confirmed(&confirmed)?;
    runtime
        .matches_active_signed_linux_v3(&confirmed)
        .map_err(|_| ())?;

    let managed =
        crate::provider_credential_enrollment::linux_activation::managed_context().ok_or(())?;
    let (root, facts) = managed.linux_activation_context().ok_or(())?;
    if !confirmed.matches_linux_signed_installation_images(&facts) {
        return Err(());
    }
    let record = LinuxEnrollmentActivationRecord {
        provider_scope: LinuxEnrollmentScope::Catalog,
        runtime_root_digest: facts.runtime_root_digest,
        desktop_image_digest: facts.desktop_image_digest,
        writer_image_digest: facts.writer_image_digest,
        daemon_image_digest: facts.daemon_image_digest,
        runtime_authority_id: facts.runtime_authority_id,
        machine_id_digest: facts.machine_id_digest,
        approved_at_unix_millis: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ())?
            .as_millis()
            .try_into()
            .map_err(|_| ())?,
    };
    installed.revalidate_confirmed(&confirmed)?;
    runtime
        .matches_active_signed_linux_v3(&confirmed)
        .map_err(|_| ())?;
    let (fresh_root, fresh_facts) = managed.linux_activation_context().ok_or(())?;
    if fresh_root != root
        || fresh_facts != facts
        || !confirmed.matches_linux_signed_installation_images(&fresh_facts)
    {
        return Err(());
    }
    runne_platform_desktop::publish_linux_activation_record(&fresh_root, &record)
        .map_err(|_| ())?;
    let (verified_root, verified_facts) = managed.linux_activation_context().ok_or(())?;
    let verified_record = crate::provider_credential_enrollment::linux_activation::read_approval_record(
        &verified_root.join(runne_api::provider_credential_enrollment::linux_activation_policy::ACTIVATION_RECORD_FILE),
    ).ok_or(())?;
    if verified_root != fresh_root
        || verified_facts != fresh_facts
        || verified_record != record
        || runne_api::provider_credential_enrollment::linux_activation_policy::evaluate_linux_enrollment(
            Some(&verified_record),
            &verified_facts,
            runne_api::provider_credential_enrollment::linux_activation_policy::LinuxEnrollmentProvider::from_id("deepseek"),
        ) != runne_api::provider_credential_enrollment::linux_activation_policy::LinuxEnrollmentDecision::Allowed
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod linux_enrollment_approval_tests {
    use super::*;

    #[test]
    fn flag_is_opt_in_and_rejects_duplicates_or_other_scopes() {
        assert!(!linux_enrollment_approval_requested(&[]).unwrap());
        assert!(
            linux_enrollment_approval_requested(&[OsString::from(
                "--approve-linux-enrollment=catalog"
            )])
            .unwrap()
        );
        assert!(
            linux_enrollment_approval_requested(&[
                OsString::from("--approve-linux-enrollment=catalog"),
                OsString::from("--approve-linux-enrollment=catalog"),
            ])
            .is_err()
        );
        assert!(
            linux_enrollment_approval_requested(&[OsString::from(
                "--approve-linux-enrollment=deepseek"
            )])
            .is_err()
        );
    }
}
