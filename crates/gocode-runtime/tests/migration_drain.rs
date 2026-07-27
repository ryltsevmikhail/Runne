use std::time::Duration;

use gocode_application::migration::types::{CohortDimension, CohortSelector, RoutingGeneration};
use gocode_runtime::migration_drain::{
    DrainDisposition, DrainRequest, MigrationDrainController, MigrationWorkId,
    RuntimeMigrationError,
};

#[tokio::test]
async fn drain_timeout_reports_remaining_work_and_is_not_success() {
    let controller = MigrationDrainController::default();
    controller
        .register_cohort(cohort_a(), routing_generation(7))
        .unwrap();
    let running = controller
        .try_admit(
            &cohort_a(),
            routing_generation(7),
            MigrationWorkId::new("binding-1").unwrap(),
        )
        .unwrap();

    let report = controller
        .drain(DrainRequest::new(
            cohort_a(),
            routing_generation(7),
            Duration::from_millis(20),
        ))
        .await
        .unwrap();

    assert_eq!(report.disposition, DrainDisposition::TimedOut);
    assert_eq!(report.still_running, vec![running.binding_id().clone()]);
    assert!(!report.is_complete());
    let before = report.clone();
    assert_eq!(
        report.validate_cutover_eligibility(),
        Err(RuntimeMigrationError::DrainTimedOut)
    );
    assert_eq!(report, before);
}

#[tokio::test]
async fn closing_one_cohort_does_not_close_unrelated_admission() {
    let controller = MigrationDrainController::default();
    controller
        .register_cohort(cohort_a(), routing_generation(7))
        .unwrap();
    controller
        .register_cohort(cohort_b(), routing_generation(7))
        .unwrap();
    controller
        .close_admission(&cohort_a(), routing_generation(7))
        .unwrap();

    assert_eq!(
        controller.try_admit(
            &cohort_a(),
            routing_generation(7),
            MigrationWorkId::new("binding-a").unwrap(),
        ),
        Err(RuntimeMigrationError::AdmissionClosed)
    );
    assert!(
        controller
            .try_admit(
                &cohort_b(),
                routing_generation(7),
                MigrationWorkId::new("binding-b").unwrap(),
            )
            .is_ok()
    );
}

#[tokio::test]
async fn completed_work_wakes_drain_and_closes_the_cohort() {
    let controller = MigrationDrainController::default();
    controller
        .register_cohort(cohort_a(), routing_generation(7))
        .unwrap();
    let work = controller
        .try_admit(
            &cohort_a(),
            routing_generation(7),
            MigrationWorkId::new("binding-complete").unwrap(),
        )
        .unwrap();
    let completion = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        work.complete().unwrap();
    });

    let report = controller
        .drain(DrainRequest::new(
            cohort_a(),
            routing_generation(7),
            Duration::from_secs(1),
        ))
        .await
        .unwrap();
    completion.await.unwrap();

    assert!(report.is_complete());
    assert_eq!(report.validate_cutover_eligibility(), Ok(()));
    assert_eq!(
        report.completed,
        vec![MigrationWorkId::new("binding-complete").unwrap()]
    );
    assert_eq!(
        controller.try_admit(
            &cohort_a(),
            routing_generation(7),
            MigrationWorkId::new("binding-late").unwrap(),
        ),
        Err(RuntimeMigrationError::AdmissionClosed)
    );
}

#[tokio::test]
async fn unresolved_effect_blocks_cutover_without_reclassifying_the_report() {
    let controller = MigrationDrainController::default();
    controller
        .register_cohort(cohort_a(), routing_generation(7))
        .unwrap();
    let work = controller
        .try_admit(
            &cohort_a(),
            routing_generation(7),
            MigrationWorkId::new("binding-uncertain").unwrap(),
        )
        .unwrap();
    controller
        .mark_uncertain(&cohort_a(), routing_generation(7), work.binding_id())
        .unwrap();

    let report = controller
        .drain(DrainRequest::new(
            cohort_a(),
            routing_generation(7),
            Duration::from_millis(20),
        ))
        .await
        .unwrap();
    let before = report.clone();

    assert_eq!(
        report.validate_cutover_eligibility(),
        Err(RuntimeMigrationError::UnresolvedEffect)
    );
    assert_eq!(report, before);
}

fn cohort_a() -> CohortSelector {
    cohort("premium")
}

fn cohort_b() -> CohortSelector {
    cohort("standard")
}

fn cohort(value: &str) -> CohortSelector {
    CohortSelector::new(vec![CohortDimension::new("client_class", value).unwrap()]).unwrap()
}

fn routing_generation(value: u64) -> RoutingGeneration {
    RoutingGeneration::new(value).unwrap()
}
