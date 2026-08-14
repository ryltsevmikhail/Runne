    #[cfg(not(target_os = "windows"))]
    #[test]
    fn sensitive_path_denied() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::create_dir_all(workspace_root.canonical_path.join(".git")).unwrap();
        fs::write(workspace_root.canonical_path.join(".git/config"), b"data").unwrap();
        let result = broker.resolve(&root, &CanonicalPath::new(".git/config").unwrap());
        assert!(matches!(result, Err(FsBrokerError::SensitivePathDenied)));
    }

    #[cfg(unix)]
    #[test]
    fn no_follow_policy_rejects_a_symlink_even_when_target_is_inside_root() {
        use std::os::unix::fs::symlink;

        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("target.txt"), b"data").unwrap();
        symlink(
            workspace_root.canonical_path.join("target.txt"),
            workspace_root.canonical_path.join("link.txt"),
        )
        .unwrap();

        let result = broker.resolve(&root, &CanonicalPath::new("link.txt").unwrap());

        assert!(matches!(result, Err(FsBrokerError::SymlinkEscapesRoot)));
    }

    #[cfg(unix)]
    #[test]
    fn no_follow_policy_rejects_a_symlink_in_an_intermediate_component() {
        use std::os::unix::fs::symlink;

        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::create_dir_all(workspace_root.canonical_path.join("real")).unwrap();
        fs::write(
            workspace_root.canonical_path.join("real/target.txt"),
            b"data",
        )
        .unwrap();
        symlink(
            workspace_root.canonical_path.join("real"),
            workspace_root.canonical_path.join("linked-dir"),
        )
        .unwrap();

        let result = broker.resolve(&root, &CanonicalPath::new("linked-dir/target.txt").unwrap());

        assert!(matches!(result, Err(FsBrokerError::NotDirectory)));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn protected_operations_are_unavailable_before_filesystem_effects() {
        let broker = test_broker();
        let workspace_root = broker.find_root("ws1").unwrap();
        let file_path = workspace_root.canonical_path.join("file.txt");
        let directory_path = workspace_root.canonical_path.join("directory");
        fs::write(&file_path, b"original").unwrap();
        fs::create_dir(&directory_path).unwrap();
        fs::write(directory_path.join("entry.txt"), b"entry").unwrap();
        let entries_before = directory_entry_names(&workspace_root.canonical_path);
        let root = RootHandle;
        let file_handle = FsHandle;
        let directory_handle = FsHandle;
        let created_handle = CreatedFsHandle;
        let path = CanonicalPath::new("file.txt").unwrap();

        assert!(matches!(
            broker.open_root("ws1"),
            Err(FsBrokerError::BackendUnavailable)
        ));

        assert!(matches!(
            broker.resolve(&root, &path),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.resolve_and_identity(&root, &path),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.read(&file_handle),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.list(&directory_handle),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.write_with_revalidation(
                &root,
                &path,
                b"replacement",
                &FsIdentity {
                    inode: 0,
                    device: 0,
                },
            ),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.create(&root, &CanonicalPath::new("new/nested.txt").unwrap()),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.write_created(created_handle, b"replacement"),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.delete(&file_handle),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert_eq!(
            fs::read(workspace_root.canonical_path.join("file.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            directory_entry_names(&workspace_root.canonical_path),
            entries_before
        );
        assert!(!workspace_root.canonical_path.join("new").exists());
        assert!(!workspace_root.canonical_path.join("created.txt").exists());
    }

    #[cfg(target_os = "windows")]
    fn directory_entry_names(directory: &std::path::Path) -> Vec<String> {
        let mut entries = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }
