//! S post-cleanup phase: existing CaseRoot checks must NOT be bypassed/reused.
use super::{context::CaseContext, process_view, record_pump::Failure};
use std::{io::ErrorKind, os::unix::fs::MetadataExt, process::ExitStatus};

pub(super) fn check(context: &CaseContext, published: Option<usize>) {
    context.record.validate();
    assert_eq!(context.deadline.0, context.record.deadline_ns);
    let view = process_view::current(context.deadline);
    assert_eq!(
        (view.process, view.parent),
        (context.record.supervisor, context.record.collector)
    );
    assert_eq!(view.pid_namespace, context.record.pid_namespace);
    assert_eq!(view.mount_namespace, context.record.mount_namespace);
    assert_eq!(view.membership, context.record.membership);
    assert_eq!(
        context.collection_root.path.to_str().unwrap(),
        context.record.collection_root
    );
    assert_eq!(
        context.collection_root.identity,
        context.record.collection_identity
    );
    context.collection_root.check(context.deadline);
    assert_eq!(context.collection_root.file.metadata().unwrap().nlink(), 2);
    // Held CaseRoot object is still owned; its NAME must already be absent.
    assert_eq!(
        context.root.path.to_str().unwrap(),
        context.record.case_root
    );
    assert_eq!(context.root.identity, context.record.case_identity);
    assert_eq!(
        std::fs::symlink_metadata(&context.root.path)
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let mut entries = std::fs::read_dir(&context.collection_root.path).unwrap();
    match published {
        None => assert!(entries.next().is_none()),
        Some(length) => {
            let entry = entries.next().unwrap().unwrap();
            assert_eq!(entry.file_name(), "provisional");
            assert!(entries.next().is_none());
            let meta = std::fs::symlink_metadata(entry.path()).unwrap();
            assert_eq!(
                (meta.uid(), meta.gid(), meta.mode(), meta.nlink()),
                (1000, 1000, 0o100600, 1)
            );
            assert_eq!(meta.dev(), context.collection_root.identity.device);
            assert_eq!(meta.len(), u64::try_from(length).unwrap());
        }
    }
    context.collection_root.check(context.deadline);
    context.deadline.check();
}

pub(super) fn after_collection(
    context: &CaseContext,
    status: ExitStatus,
    length: usize,
) -> Result<(), Failure> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check(context, Some(length))
    }))
    .map_err(|_| Failure::collected("final collection phase validation", status))
}
