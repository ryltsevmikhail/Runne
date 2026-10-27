//! Readiness is only a hint; the helper must authenticate the actual marker/record.
use super::{context::CaseContext, record_protocol::Name};
use std::{io::ErrorKind, os::unix::fs::MetadataExt, time::Duration};

pub(super) fn wait(context: &CaseContext, name: Name) {
    let path = context.root.path.join(format!("{}.complete", name.stem()));
    loop {
        context.check_roots();
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                assert!(meta.is_dir());
                assert_eq!((meta.uid(), meta.gid(), meta.mode()), (1000, 1000, 0o40700));
                assert_eq!(meta.dev(), context.root.identity.device);
                assert_eq!(meta.nlink(), 2);
                break;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => panic!("completion hint: {error}"),
        }
        std::thread::sleep(context.deadline.remaining().min(Duration::from_millis(1)));
    }
}
