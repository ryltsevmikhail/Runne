    #[test]
    fn resolve_rejects_absolute_path() {
        assert!(CanonicalPath::new("/etc/passwd").is_err());
    }

    #[test]
    fn resolve_rejects_parent_directory_escape() {
        assert!(CanonicalPath::new("../escape").is_err());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn resolve_and_read_valid_path() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("test.txt"), b"hello").unwrap();
        let handle = broker
            .resolve(&root, &CanonicalPath::new("test.txt").unwrap())
            .unwrap();
        assert_eq!(broker.read(&handle).unwrap(), b"hello");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn read_rejected_when_policy_read_allowed_false() {
        let mut broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("test.txt"), b"hello").unwrap();
        let handle = broker
            .resolve(&root, &CanonicalPath::new("test.txt").unwrap())
            .unwrap();
        broker.roots[0].policy.read_allowed = false;

        let result = broker.read(&handle);

        assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn handles_are_rejected_by_a_different_broker_with_the_same_root_id() {
        let temporary_root_a = std::env::temp_dir().join(format!(
            "gocode_fs_cross_broker_a_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let temporary_root_b = std::env::temp_dir().join(format!(
            "gocode_fs_cross_broker_b_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&temporary_root_a);
        let _ = fs::remove_dir_all(&temporary_root_b);
        fs::create_dir_all(temporary_root_a.join("directory")).unwrap();
        fs::create_dir_all(&temporary_root_b).unwrap();
        fs::write(temporary_root_a.join("secret.txt"), b"secret").unwrap();
        fs::write(temporary_root_a.join("directory/entry.txt"), b"entry").unwrap();

        let policy = WorkspacePolicy {
            read_allowed: true,
            write_allowed: true,
            create_allowed: true,
            delete_allowed: true,
            symlink_policy: SymlinkPolicy::NoFollow,
        };
        let broker_a = FilesystemBroker::new(vec![WorkspaceRoot {
            root_id: "shared".into(),
            canonical_path: fs::canonicalize(&temporary_root_a).unwrap(),
            policy: policy.clone(),
        }]);
        let broker_b = FilesystemBroker::new(vec![WorkspaceRoot {
            root_id: "shared".into(),
            canonical_path: fs::canonicalize(&temporary_root_b).unwrap(),
            policy,
        }]);
        let root_a = broker_a.open_root("shared").unwrap();
        let file_handle = broker_a
            .resolve(&root_a, &CanonicalPath::new("secret.txt").unwrap())
            .unwrap();
        let directory_handle = broker_a
            .resolve(&root_a, &CanonicalPath::new("directory").unwrap())
            .unwrap();

        assert!(matches!(
            broker_b.read(&file_handle),
            Err(FsBrokerError::PermissionDenied)
        ));
        assert!(matches!(
            broker_b.list(&directory_handle),
            Err(FsBrokerError::PermissionDenied)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn root_handle_keeps_operations_inside_the_admitted_directory_after_path_replacement() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace = broker.find_root("ws1").unwrap().canonical_path.clone();
        let path = CanonicalPath::new("file.txt").unwrap();
        fs::write(workspace.join("file.txt"), b"admitted").unwrap();
        let moved = workspace.with_file_name(format!(
            "gocode-fs-admitted-{}",
            uuid::Uuid::now_v7()
        ));
        fs::rename(&workspace, &moved).unwrap();
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("file.txt"), b"replacement").unwrap();

        let handle = broker.resolve(&root, &path).unwrap();

        assert_eq!(broker.read(&handle).unwrap(), b"admitted");
        assert_eq!(fs::read(workspace.join("file.txt")).unwrap(), b"replacement");
    }
