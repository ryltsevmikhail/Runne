//! Fresh controlled workspace observations; no historical path or mutation.
use super::{context::CaseContext, fixture_paths, io, metadata::Area};
use std::{io::ErrorKind, path::PathBuf};

pub(super) fn workspace(context: &CaseContext, area: &Area) -> PathBuf {
    area.validate(context);
    let root = context.root.path.join(&area.nested).join("workspace");
    fixture_paths::directory(&root, context);
    root
}

pub(super) fn pending(context: &CaseContext, area: &Area) {
    let root = workspace(context, area);
    for name in ["proceed", "forbidden-marker"] {
        context.deadline.check();
        match std::fs::symlink_metadata(root.join(name)) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            value => panic!("pending workload path must be absent: {value:?}"),
        }
    }
    let marker = root.join("effect-marker");
    fixture_paths::regular(&marker, context);
    assert_eq!(
        io::bounded(&marker, 4, context.deadline).as_bytes(),
        b"once"
    );
    context.deadline.check();
}
