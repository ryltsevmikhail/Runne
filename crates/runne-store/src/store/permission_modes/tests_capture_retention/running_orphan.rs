//! Dedicated bounded guest-only running-child crash/recovery regression.
//! No normal CLI/runtime service activation, host target route or fallback.
use super::{ceremony, fixture, target};
#[path = "running_orphan_after_ack.rs"]
mod after_ack;
#[path = "../tests_admitted_retention/approval.rs"]
mod approval;
#[path = "running_orphan_area_path.rs"]
mod area_path;
#[path = "running_orphan_association.rs"]
mod association;
#[path = "running_orphan_attempt.rs"]
mod attempt;
#[path = "running_orphan_bootstrap.rs"]
mod bootstrap;
#[path = "running_orphan_cancel.rs"]
mod cancel;
#[path = "running_orphan_capture.rs"]
mod capture;
#[path = "running_orphan_case_cleanup.rs"]
mod case_cleanup;
#[path = "running_orphan_chain.rs"]
mod chain;
#[path = "running_orphan_checkpoint.rs"]
mod checkpoint;
#[path = "running_orphan_clock.rs"]
mod clock;
#[path = "running_orphan_collection_phase.rs"]
mod collection_phase;
#[path = "running_orphan_collection_response.rs"]
mod collection_response;
#[path = "running_orphan_collection_transport.rs"]
mod collection_transport;
#[path = "running_orphan_context.rs"]
mod context;
#[path = "running_orphan_control.rs"]
mod control;
#[path = "running_orphan_control_receipts.rs"]
mod control_receipts;
#[path = "running_orphan_control_result.rs"]
mod control_result;
#[path = "running_orphan_fixture_paths.rs"]
mod fixture_paths;
#[path = "running_orphan_held_area.rs"]
mod held_area;
#[path = "running_orphan_helper_failure.rs"]
mod helper_failure;
#[path = "running_orphan_io.rs"]
mod io;
#[path = "running_orphan_live.rs"]
mod live;
#[path = "running_orphan_metadata.rs"]
mod metadata;
#[path = "running_orphan_model.rs"]
mod model;
#[cfg(test)]
#[path = "running_orphan_model_tests.rs"]
mod model_tests;
#[path = "running_orphan_native.rs"]
mod native;
#[path = "running_orphan_observation_store.rs"]
mod observation_store;
#[path = "running_orphan_observations.rs"]
mod observations;
#[path = "running_orphan_orphan.rs"]
mod orphan;
#[path = "running_orphan_process_view.rs"]
mod process_view;
#[path = "running_orphan_record_protocol.rs"]
mod record_protocol;
#[path = "running_orphan_record_publication.rs"]
mod record_publication;
#[path = "running_orphan_record_pump.rs"]
mod record_pump;
#[path = "running_orphan_record_transport.rs"]
mod record_transport;
#[path = "running_orphan_record_validation.rs"]
mod record_validation;
#[path = "running_orphan_records.rs"]
mod records;
#[path = "running_orphan_recovery.rs"]
mod recovery;
#[path = "running_orphan_recovery_receipts.rs"]
mod recovery_receipts;
#[path = "running_orphan_recovery_result.rs"]
mod recovery_result;
#[path = "running_orphan_role.rs"]
mod role;
#[path = "running_orphan_role_child.rs"]
mod role_child;
#[path = "running_orphan_setup.rs"]
mod setup;
#[path = "running_orphan_snapshot.rs"]
mod snapshot;
#[path = "running_orphan_supervisor.rs"]
mod supervisor;
#[path = "running_orphan_uuid_text.rs"]
mod uuid_text;
#[path = "running_orphan_wait_record.rs"]
mod wait_record;
#[path = "running_orphan_wire.rs"]
mod wire;
#[cfg(test)]
#[path = "running_orphan_wire_tests.rs"]
mod wire_tests;
#[path = "running_orphan_workspace.rs"]
mod workspace;
#[path = "running_orphan_writer.rs"]
mod writer;

#[test]
fn running_child_writer_abort_recovers_unknown() {
    match role::current() {
        Some(role::Role::Writer) => writer::run(&context::CaseContext::inherit_child()),
        Some(role::Role::Recovery) => recovery::run(&context::CaseContext::inherit_child()),
        None => {
            let context = context::CaseContext::new_supervisor();
            let case = supervisor::run(&context);
            assert_eq!(case.writer_signal, 6);
            eprintln!(
                "R05_RUNNING_SUBJECT_V1 branch={} writer_signal={} recovery={} case_removed=1 control_collected=1 original_area_removed=1",
                case.branch.label(),
                case.writer_signal,
                case.recovery_pid
            );
            let status =
                helper_failure::require(collection_transport::publish(&context, &case.provisional));
            assert!(status.success());
            // Returning is only subject libtest0. C/init must independently
            // collect S, original adopted N/ECHILD and actual owned cleanup.
        }
    }
}
