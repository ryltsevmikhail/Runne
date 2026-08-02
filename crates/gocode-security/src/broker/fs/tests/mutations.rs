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
    fn write_is_unavailable_before_identity_revalidation() {
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
    fn write_is_unavailable_without_changing_file_bytes() {
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
    fn write_is_unavailable_when_policy_write_allowed_false() {
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

    #[cfg(all(not(unix), not(target_os = "windows")))]
    #[test]
    fn write_rejected_when_policy_write_allowed_false() {
        let mut broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let path = CanonicalPath::new("file.txt").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
        let (_, identity) = broker.resolve_and_identity(&root, &path).unwrap();
        broker.roots[0].policy.write_allowed = false;

        let result = broker.write_with_revalidation(&root, &path, b"replacement", &identity);

        assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
    }

    #[cfg(unix)]
    #[test]
    fn create_is_unavailable_without_creating_files_or_directories() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(
            workspace_root.canonical_path.join("existing.txt"),
            b"original",
        )
        .unwrap();
        let entries_before = directory_entry_names(&workspace_root.canonical_path);

        let result = broker.create(&root, &CanonicalPath::new("new/nested.txt").unwrap());

        assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
        assert_eq!(
            fs::read(workspace_root.canonical_path.join("existing.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            directory_entry_names(&workspace_root.canonical_path),
            entries_before
        );
        assert!(!workspace_root.canonical_path.join("new").exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_created_is_unavailable_without_changing_file_bytes() {
        let broker = test_broker();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(
            workspace_root.canonical_path.join("existing.txt"),
            b"original",
        )
        .unwrap();
        let entries_before = directory_entry_names(&workspace_root.canonical_path);
        let created = CreatedFsHandle {
            binding: broker.binding.clone(),
        };

        let result = broker.write_created(&created, b"replacement");

        assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
        assert_eq!(
            fs::read(workspace_root.canonical_path.join("existing.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            directory_entry_names(&workspace_root.canonical_path),
            entries_before
        );
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
