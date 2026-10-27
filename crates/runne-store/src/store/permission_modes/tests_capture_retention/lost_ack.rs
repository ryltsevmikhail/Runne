//! Draft guest-only primitive guard controls. Not a receipt/crash acceptance test.
#[path = "running_orphan_clock.rs"]
mod clock;
#[path = "running_orphan_context.rs"]
mod context;
#[path = "running_orphan_io.rs"]
mod io;
#[path = "running_orphan_model.rs"]
mod model;
#[path = "running_orphan_process_view.rs"]
mod process_view;
#[path = "running_orphan_association.rs"]
mod association;
#[path = "running_orphan_uuid_text.rs"]
mod uuid_text;
#[path = "lost_ack_channel.rs"]
mod channel;
#[path = "lost_ack_owned_role.rs"]
mod owned_role;
#[path = "lost_ack_zero_response.rs"]
mod zero_response;
#[path = "lost_ack_transport_fd.rs"]
mod transport_fd;
#[path = "lost_ack_guard_roles.rs"]
mod guard_roles;

#[test]
fn guard_history() {
    match guard_roles::current() {
        Some(mode) => guard_roles::child(&context::CaseContext::inherit_child(), mode),
        None => {
            let context = context::CaseContext::new_supervisor();
            guard_roles::regressions(&context);
            guard_roles::association_and_missing_observation_controls(&context);
            // No native child/workspace/Store is created by these controls.
            // Each direct role handle has been collected before its function returns.
            context.check_roots();
            assert!(std::fs::read_dir(&context.root.path).unwrap().next().is_none());
            let path = context.root.path.clone();
            std::fs::remove_dir(&path).unwrap();
            assert_eq!(std::fs::symlink_metadata(&path).unwrap_err().kind(),
                std::io::ErrorKind::NotFound);
            context.collection_root.check(context.deadline);
            assert!(std::fs::read_dir(&context.collection_root.path).unwrap().next().is_none());
            context.deadline.check();
            drop(context); // close both held roots before subject libtest returns
            // This is only subject progress. Independent collector/init must
            // establish subject status, descendants/ECHILD and final RAM cleanup.
            eprintln!("R05_GUARD_SUBJECT_V1 controls_returned=1 case_removed=1");
        }
    }
}

// Pure SQLite Reader regressions; no native effect or crash acceptance authority.
#[path = "lost_ack_reader/snapshot.rs"]
mod logical_reader;
