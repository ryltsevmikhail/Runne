    use super::*;

    fn test_broker() -> FilesystemBroker {
        let temporary_root = std::env::temp_dir().join(format!(
            "gocode_fs_test_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&temporary_root);
        fs::create_dir_all(&temporary_root).unwrap();
        FilesystemBroker::new(vec![WorkspaceRoot {
            root_id: "ws1".into(),
            canonical_path: fs::canonicalize(temporary_root).unwrap(),
            policy: WorkspacePolicy {
                read_allowed: true,
                write_allowed: true,
                create_allowed: true,
                delete_allowed: true,
                symlink_policy: SymlinkPolicy::NoFollow,
            },
        }])
    }

    #[cfg(unix)]
    fn create_or_skip_unsupported_tmpfile(
        broker: &FilesystemBroker,
        root: &RootHandle,
        path: &str,
    ) -> Option<CreatedFsHandle> {
        match broker.create(root, &CanonicalPath::new(path).unwrap()) {
            Ok(handle) => Some(handle),
            Err(FsBrokerError::BackendUnavailable | FsBrokerError::MutationUnavailable) => None,
            Err(error) => panic!("created file setup failed unexpectedly: {error:?}"),
        }
    }
