//! Remove only this exclusive guest CaseRoot after all actual mutators collected.
use super::{context::CaseContext, fixture_paths, metadata::Area, record_protocol::Name};
use std::{collections::BTreeSet, io::ErrorKind, os::unix::fs::MetadataExt};

pub(super) fn remove(context: &CaseContext, original: &Area, control: &Area) {
    context.check_roots();
    assert_ne!(original.nested, control.nested);
    let names = [
        Name::OriginalArea,
        Name::BeforeGo,
        Name::AfterReady,
        Name::RunningCut,
        Name::SupervisorAck,
        Name::AfterAck,
        Name::RecoveryResult,
        Name::ControlResult,
    ];
    let mut expected = BTreeSet::new();
    // Both fresh fixture roots must still exist: S retains control Fixture.
    for area in [original, control] {
        fixture_paths::component(&area.nested);
        fixture_paths::directory(&context.root.path.join(&area.nested), context);
        expected.insert(area.nested.clone());
    }
    for name in names {
        expected.insert(format!("{}.json", name.stem()));
        expected.insert(format!("{}.complete", name.stem()));
    }
    let actual: BTreeSet<_> = std::fs::read_dir(&context.root.path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(actual, expected);
    for name in names {
        let file = context.root.path.join(format!("{}.json", name.stem()));
        fixture_paths::regular(&file, context);
        let meta = std::fs::symlink_metadata(&file).unwrap();
        assert_eq!(meta.mode(), 0o100600);
        assert_eq!(meta.nlink(), 1);
        assert!((1..=16384).contains(&meta.len()));
        std::fs::remove_file(file).unwrap();
        let marker = context.root.path.join(format!("{}.complete", name.stem()));
        fixture_paths::directory(&marker, context);
        assert!(std::fs::read_dir(&marker).unwrap().next().is_none());
        std::fs::remove_dir(marker).unwrap();
    }
    for area in [original, control] {
        context.check_roots();
        let path = context.root.path.join(&area.nested);
        fixture_paths::directory(&path, context);
        std::fs::remove_dir_all(&path).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap_err().kind(),
            ErrorKind::NotFound
        );
    }
    context.check_roots();
    assert!(
        std::fs::read_dir(&context.root.path)
            .unwrap()
            .next()
            .is_none()
    );
    std::fs::remove_dir(&context.root.path).unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&context.root.path)
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    // Held descriptor remains owned, but named root is now absent. Do not check_roots again.
    context.collection_root.check(context.deadline);
    assert_eq!(context.collection_root.file.metadata().unwrap().nlink(), 2);
    assert!(
        std::fs::read_dir(&context.collection_root.path)
            .unwrap()
            .next()
            .is_none()
    );
    context.deadline.check();
}
