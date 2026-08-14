#[cfg(unix)]
#[test]
fn resolved_handle_reads_the_held_file_descriptor() {
    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    let path = workspace_root.canonical_path.join("test.txt");
    fs::write(&path, b"original").unwrap();
    let handle = broker
        .resolve(&root, &CanonicalPath::new("test.txt").unwrap())
        .unwrap();
    let replacement = workspace_root.canonical_path.join("test.txt.replacement");
    fs::write(&replacement, b"replacement").unwrap();
    fs::rename(replacement, path).unwrap();

    assert_eq!(broker.read(&handle).unwrap(), b"original");
}

#[cfg(unix)]
#[test]
fn existing_write_is_unavailable_after_path_replacement() {
    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let path = CanonicalPath::new("file.txt").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
    let (_, identity_before) = broker.resolve_and_identity(&root, &path).unwrap();
    let temporary_path = workspace_root.canonical_path.join("file.txt.tmp");
    fs::write(&temporary_path, b"new content").unwrap();
    fs::rename(
        &temporary_path,
        workspace_root.canonical_path.join("file.txt"),
    )
    .unwrap();
    let result = broker.write_with_revalidation(&root, &path, b"data", &identity_before);
    assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
    assert_eq!(
        fs::read(workspace_root.canonical_path.join("file.txt")).unwrap(),
        b"new content"
    );
}

#[cfg(unix)]
#[test]
fn existing_write_is_unavailable_without_changing_file_bytes() {
    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let path = CanonicalPath::new("file.txt").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
    let (_, identity) = broker.resolve_and_identity(&root, &path).unwrap();

    let result = broker.write_with_revalidation(&root, &path, b"replacement", &identity);

    assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
    assert_eq!(
        fs::read(workspace_root.canonical_path.join("file.txt")).unwrap(),
        b"original"
    );
}

#[cfg(unix)]
#[test]
fn existing_write_is_unavailable_regardless_of_workspace_policy() {
    let mut broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let path = CanonicalPath::new("file.txt").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
    let (_, identity) = broker.resolve_and_identity(&root, &path).unwrap();
    broker.roots[0].policy.write_allowed = false;

    let result = broker.write_with_revalidation(&root, &path, b"replacement", &identity);

    assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
}

#[cfg(unix)]
#[test]
fn existing_write_is_unavailable_after_file_symlink_substitution() {
    use std::os::unix::fs::symlink;

    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let path = CanonicalPath::new("file.txt").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    let target = workspace_root.canonical_path.join("outside.txt");
    fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
    fs::write(&target, b"outside").unwrap();
    let (_, identity) = broker.resolve_and_identity(&root, &path).unwrap();
    fs::remove_file(workspace_root.canonical_path.join("file.txt")).unwrap();
    symlink(&target, workspace_root.canonical_path.join("file.txt")).unwrap();

    let result = broker.write_with_revalidation(&root, &path, b"replacement", &identity);

    assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
    assert_eq!(fs::read(target).unwrap(), b"outside");
}

#[cfg(unix)]
#[test]
fn existing_write_is_unavailable_after_parent_symlink_substitution() {
    use std::os::unix::fs::symlink;

    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let path = CanonicalPath::new("parent/file.txt").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    let parent = workspace_root.canonical_path.join("parent");
    let outside = workspace_root.canonical_path.join("outside");
    fs::create_dir(&parent).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(parent.join("file.txt"), b"original").unwrap();
    fs::write(outside.join("file.txt"), b"outside").unwrap();
    let (_, identity) = broker.resolve_and_identity(&root, &path).unwrap();
    fs::remove_file(parent.join("file.txt")).unwrap();
    fs::remove_dir(&parent).unwrap();
    symlink(&outside, &parent).unwrap();

    let result = broker.write_with_revalidation(&root, &path, b"replacement", &identity);

    assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
    assert_eq!(fs::read(outside.join("file.txt")).unwrap(), b"outside");
}

#[cfg(all(not(unix), not(target_os = "windows")))]
#[test]
fn existing_write_is_unavailable_in_the_fallback_backend() {
    let mut broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let path = CanonicalPath::new("file.txt").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
    let (_, identity) = broker.resolve_and_identity(&root, &path).unwrap();
    broker.roots[0].policy.write_allowed = false;

    let result = broker.write_with_revalidation(&root, &path, b"replacement", &identity);

    assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
}

#[cfg(unix)]
#[test]
fn create_rejects_an_existing_file_without_overwriting_it() {
    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    fs::write(
        workspace_root.canonical_path.join("existing.txt"),
        b"original",
    )
    .unwrap();
    let result = broker.create(&root, &CanonicalPath::new("existing.txt").unwrap());

    assert!(result.is_err());
    assert_eq!(
        fs::read(workspace_root.canonical_path.join("existing.txt")).unwrap(),
        b"original"
    );
}

#[cfg(unix)]
#[test]
fn write_created_writes_only_the_fd_bound_created_file() {
    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    fs::write(
        workspace_root.canonical_path.join("existing.txt"),
        b"original",
    )
    .unwrap();
    let created = broker
        .create(&root, &CanonicalPath::new("created.txt").unwrap())
        .unwrap();

    let result = broker.write_created(created, b"replacement");

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        fs::read(workspace_root.canonical_path.join("existing.txt")).unwrap(),
        b"original"
    );
    assert_eq!(
        fs::read(workspace_root.canonical_path.join("created.txt")).unwrap(),
        b"replacement"
    );
}

#[cfg(unix)]
#[test]
fn write_created_rejects_a_handle_from_another_broker_without_partial_mutation() {
    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    let created = broker
        .create(&root, &CanonicalPath::new("created.txt").unwrap())
        .unwrap();

    let other_broker = FilesystemBroker::new(vec![WorkspaceRoot {
        root_id: "ws1".into(),
        canonical_path: workspace_root.canonical_path.clone(),
        policy: WorkspacePolicy {
            read_allowed: true,
            write_allowed: true,
            create_allowed: true,
            delete_allowed: true,
            symlink_policy: SymlinkPolicy::NoFollow,
        },
    }]);
    let result = other_broker.write_created(created, b"replacement");

    assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
    assert!(!workspace_root.canonical_path.join("created.txt").exists());
}

#[cfg(unix)]
#[test]
fn delete_is_unavailable_without_removing_file_or_directory_entries() {
    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    fs::write(workspace_root.canonical_path.join("test.txt"), b"hello").unwrap();
    let handle = broker
        .resolve(&root, &CanonicalPath::new("test.txt").unwrap())
        .unwrap();
    let entries_before = directory_entry_names(&workspace_root.canonical_path);

    let result = broker.delete(&handle);

    assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
    assert_eq!(
        fs::read(workspace_root.canonical_path.join("test.txt")).unwrap(),
        b"hello"
    );
    assert_eq!(
        directory_entry_names(&workspace_root.canonical_path),
        entries_before
    );
}

#[cfg(unix)]
#[test]
fn list_rejected_when_policy_read_allowed_false() {
    let mut broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    fs::create_dir_all(workspace_root.canonical_path.join("directory")).unwrap();
    fs::write(
        workspace_root.canonical_path.join("directory/entry.txt"),
        b"data",
    )
    .unwrap();
    let handle = broker
        .resolve(&root, &CanonicalPath::new("directory").unwrap())
        .unwrap();
    broker.roots[0].policy.read_allowed = false;

    let result = broker.list(&handle);

    assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
}

#[cfg(all(not(unix), not(target_os = "windows")))]
#[test]
fn fallback_list_rejected_when_policy_read_allowed_false_without_entry_disclosure() {
    let mut broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    fs::create_dir_all(workspace_root.canonical_path.join("directory")).unwrap();
    fs::write(
        workspace_root
            .canonical_path
            .join("directory/secret-entry.txt"),
        b"data",
    )
    .unwrap();
    let handle = broker
        .resolve(&root, &CanonicalPath::new("directory").unwrap())
        .unwrap();
    broker.roots[0].policy.read_allowed = false;

    let result = broker.list(&handle);

    assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
}

#[cfg(unix)]
fn directory_entry_names(directory: &std::path::Path) -> Vec<String> {
    let mut entries = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}
