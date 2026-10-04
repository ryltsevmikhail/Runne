use super::unavailable_taskrun_host::UnavailableTaskRunHost;
use super::*;
use runne_api::ApiActor;
use runne_domain::task_run::SelectedProviderProfile;
use std::sync::{Arc, Mutex};

pub(super) fn host_with_submit_capture(
    capabilities: &'static [&'static str],
    pinned_model: Option<&str>,
    profile_models: Vec<(SelectedProviderProfile, String)>,
) -> (
    SecureLocalHttpHost,
    Arc<Mutex<Vec<runne_api::SubmitTaskRunCommand>>>,
) {
    let submissions = Arc::new(Mutex::new(Vec::new()));
    let profiles = profile_models
        .iter()
        .map(|(profile, _)| profile.clone())
        .collect();
    let host = UnavailableTaskRunHost {
        submissions: Some(Arc::clone(&submissions)),
    };
    let state = TaskRunHttpState::new(
        host,
        ApiActor::new("runne-http-test").unwrap(),
        pinned_model.map(str::to_owned),
    )
    .with_allowed_profiles(profiles)
    .with_profile_models(profile_models);
    (
        super::host_with_task_run_state(capabilities, state),
        submissions,
    )
}
