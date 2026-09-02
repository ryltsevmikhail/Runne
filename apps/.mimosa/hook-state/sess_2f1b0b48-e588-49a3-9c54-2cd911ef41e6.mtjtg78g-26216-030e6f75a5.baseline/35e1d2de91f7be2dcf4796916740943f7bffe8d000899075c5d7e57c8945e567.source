#[path = "../src/external_activation.rs"]
mod external_activation;

use external_activation::{ActivationEvent, ActivationTarget, parse_activation};

const TASK_RUN: &str = "018f2e3a-7000-7000-8000-000000000212";
const APPROVAL: &str = "018f2e3a-7000-7000-8000-000000000213";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000214";

#[test]
fn parses_bounded_task_run_activation_without_raw_url() {
    let target = parse_activation(&format!(
        "runne://open?v=1&runtime=gocode-local-runtime%2F2&workspace={WORKSPACE}&taskrun={TASK_RUN}&event=approval"
    ))
    .expect("valid activation");

    assert_eq!(
        target,
        ActivationTarget {
            runtime: Some("gocode-local-runtime/2".to_owned()),
            project_id: None,
            workspace_id: Some(WORKSPACE.to_owned()),
            task_run_id: Some(TASK_RUN.to_owned()),
            approval_id: None,
            event: Some(ActivationEvent::Approval),
        }
    );
}

#[test]
fn parses_approval_activation_as_route_data_only() {
    let target = parse_activation(&format!("runne://open?v=1&approval={APPROVAL}"))
        .expect("valid approval activation");

    assert_eq!(target.approval_id.as_deref(), Some(APPROVAL));
    assert!(target.task_run_id.is_none());
}

#[test]
fn rejects_unknown_duplicate_or_secret_shaped_parameters() {
    for value in [
        "runne://open?v=1&taskrun=018f2e3a-7000-7000-8000-000000000212&extra=x",
        "runne://open?v=1&taskrun=018f2e3a-7000-7000-8000-000000000212&taskrun=018f2e3a-7000-7000-8000-000000000213",
        "runne://open?v=1&token=not-allowed",
        "runne://open?v=1&secret=not-allowed",
        "runne://open?v=1&taskrun=018f2e3a-7000-7000-8000-000000000211#fragment",
    ] {
        assert!(parse_activation(value).is_err(), "accepted {value}");
    }
}

#[test]
fn rejects_missing_version_invalid_identity_and_ambiguous_unicode() {
    for value in [
        "runne://open&taskrun=018f2e3a-7000-7000-8000-000000000212",
        "runne://open?v=2&taskrun=018f2e3a-7000-7000-8000-000000000212",
        "runne://open?v=1&taskrun=018f2e3a-6000-6000-8000-000000000212",
        "runne://open?v=1&taskrun=018f2e3a-7000-7000-8000-000000000212%CC%81",
        "runne://open?v=1&event=unknown",
    ] {
        assert!(parse_activation(value).is_err(), "accepted {value}");
    }
}
