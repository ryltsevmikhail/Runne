//! Only newly created guest CaseRoot descendants; never historical databases.
use super::context::CaseContext;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

pub(super) fn component(name: &str) {
    assert!(!name.is_empty() && name.len() <= 255);
    assert!(
        name.bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
    );
    assert!(!matches!(name, "." | ".."));
    let mut parts = Path::new(name).components();
    assert!(matches!(parts.next(), Some(Component::Normal(_))));
    assert!(parts.next().is_none());
}

pub(super) fn directory(path: &Path, context: &CaseContext) {
    context.check_roots();
    assert!(path.starts_with(&context.root.path));
    assert_eq!(
        path.to_str().unwrap(),
        path.components()
            .collect::<std::path::PathBuf>()
            .to_str()
            .unwrap()
    );
    for item in path.ancestors() {
        if !item.starts_with(&context.root.path) {
            break;
        }
        let meta = std::fs::symlink_metadata(item).unwrap();
        assert!(meta.is_dir());
        assert_eq!(
            (meta.uid(), meta.gid(), meta.dev()),
            (1000, 1000, context.root.identity.device)
        );
        assert_eq!(std::fs::canonicalize(item).unwrap(), item);
    }
    context.deadline.check();
}

pub(super) fn regular(path: &Path, context: &CaseContext) {
    component(path.file_name().unwrap().to_str().unwrap());
    directory(path.parent().unwrap(), context);
    let meta = std::fs::symlink_metadata(path).unwrap();
    assert!(meta.is_file());
    assert_eq!(
        (meta.uid(), meta.gid(), meta.dev()),
        (1000, 1000, context.root.identity.device)
    );
    context.deadline.check();
}
