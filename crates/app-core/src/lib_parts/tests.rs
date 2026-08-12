    use super::{
        AppCore, BootstrapState, CanonicalId, RuntimeAvailability, RuntimeLifecycleStatus,
        RuntimeMode, StoredConversationReference, StoredConversationReferenceV1, load_bootstrap,
    };
    use crate::replay::StableRuntimeIdentity;
    use gocode_local_store::LocalStore;

    #[test]
    fn bootstrap_reports_saved_theme_without_runtime_secrets() {
        let directory = tempfile::tempdir().expect("temp directory");
        let mut store =
            LocalStore::open(&directory.path().join("profile.sqlite3")).expect("open store");
        store
            .set_setting("appearance.theme", "light")
            .expect("save theme");

        assert_eq!(
            BootstrapState {
                theme: "light".to_owned(),
                runtime_mode: RuntimeMode::ExternalLocal,
                runtime: RuntimeAvailability::Unconfigured,
                runtime_lifecycle: RuntimeLifecycleStatus::External,
                runtime_failure: None,
            },
            load_bootstrap(&store).expect("load bootstrap")
        );
    }

    #[test]
    fn theme_change_is_persisted_by_app_core() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        let core = AppCore::open(&path).expect("open core");

        core.set_theme("light").expect("save theme");
        drop(core);

        let reopened = AppCore::open(&path).expect("reopen core");
        assert_eq!("light", reopened.bootstrap().expect("load bootstrap").theme);
    }

    #[test]
    fn canonical_recent_root_makes_it_available_after_app_restart() {
        let directory = tempfile::tempdir().expect("temp directory");
        let database_path = directory.path().join("profile.sqlite3");
        let mut store = LocalStore::open(&database_path).expect("open store");
        store
            .record_recent_root(
                "01890e00-0000-7000-8000-000000000001",
                "01890e00-0000-7000-8000-000000000002",
                "Project one",
                1,
                "native-root-1",
            )
            .expect("record root");
        drop(store);

        let reopened = AppCore::open(&database_path).expect("reopen core");
        let projects = reopened.list_projects().expect("list projects");
        let restored = reopened
            .get_project("01890e00-0000-7000-8000-000000000001")
            .expect("get project")
            .into_iter()
            .next()
            .expect("stored project");

        assert_eq!(projects, vec![restored.clone()]);
        assert_eq!(restored.project_id, "01890e00-0000-7000-8000-000000000001");
        assert_eq!(restored.workspace_id, "01890e00-0000-7000-8000-000000000002");
        assert!(!serde_json::to_string(&restored).expect("serialize").contains("native-root-1"));
    }

    #[test]
    fn diagnostics_expose_counts_and_generations_without_project_paths() {
        let directory = tempfile::tempdir().expect("temp directory");
        let database_path = directory.path().join("profile.sqlite3");
        let project_path = directory.path().join("private-project-name");
        std::fs::create_dir(&project_path).expect("create project directory");
        let core = AppCore::open(&database_path).expect("open core");
        core.open_local_project(&project_path)
            .expect("open project");

        let diagnostics = core
            .diagnostics("0.1.0", "macos")
            .expect("read diagnostics");
        let rendered = format!("{diagnostics:?}");

        assert_eq!(diagnostics.app_version, "0.1.0");
        assert_eq!(diagnostics.platform, "macos");
        assert_eq!(diagnostics.database_schema_version, 5);
        assert_eq!(diagnostics.database_generation, 1);
        assert_eq!(diagnostics.project_count, 1);
        assert_eq!(diagnostics.runtime, RuntimeAvailability::Unconfigured);
        assert!(!rendered.contains("private-project-name"));
        assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn conversation_reference_v2_contains_only_stable_authenticated_identity() {
        let command_id = CanonicalId::now_v7();
        let reference = StoredConversationReference::V1(StoredConversationReferenceV1 {
            schema_version: 1,
            conversation_id: CanonicalId::now_v7(),
            workspace_id: CanonicalId::now_v7(),
            create_command_id: command_id,
            idempotency_key: command_id.to_string(),
        });
        let identity = StableRuntimeIdentity {
            authority: "018f2e3a-7000-7000-8000-000000000120".to_owned(),
            principal: "local-owner".to_owned(),
            lineage: "018f2e3a-7000-7000-8000-000000000121".to_owned(),
            profile_id: "gocode-ui-client/1".to_owned(),
            schema_hash: "11".repeat(32),
            capability_digest: "22".repeat(32),
            binding_digest: "33".repeat(32),
            launch_generation: 9,
        };

        let bound = identity.bind_reference(&reference);
        assert!(identity.matches_reference(&bound));
        for mutate in [
            |value: &mut StableRuntimeIdentity| value.authority = "changed".to_owned(),
            |value: &mut StableRuntimeIdentity| value.principal = "changed".to_owned(),
            |value: &mut StableRuntimeIdentity| value.lineage = "changed".to_owned(),
            |value: &mut StableRuntimeIdentity| value.profile_id = "changed".to_owned(),
            |value: &mut StableRuntimeIdentity| value.schema_hash = "changed".to_owned(),
            |value: &mut StableRuntimeIdentity| value.capability_digest = "changed".to_owned(),
        ] {
            let mut changed = identity.clone();
            mutate(&mut changed);
            assert!(!changed.matches_reference(&bound));
        }

        let serialized = serde_json::to_value(bound).expect("serialize");
        let object = serialized.as_object().expect("reference object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "capabilityDigest",
                "conversationId",
                "createCommandId",
                "idempotencyKey",
                "lineage",
                "principal",
                "profileId",
                "runtimeAuthority",
                "schemaHash",
                "schemaVersion",
                "workspaceId",
            ]
        );
        assert_eq!(object["schemaVersion"], 2);
        let encoded = serde_json::to_string(object).expect("encode reference");
        for forbidden in [
            "instance",
            "generation",
            "session",
            "endpoint",
            "secret",
            "cursor",
            "certificate",
            "credential",
        ] {
            assert!(!encoded.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn reference_identity_conflict_is_fatal_and_does_not_rewrite_reference() {
        let directory = tempfile::tempdir().expect("temp directory");
        let database_path = directory.path().join("profile.sqlite3");
        let project_path = directory.path().join("project");
        std::fs::create_dir(&project_path).expect("create project");
        let core = AppCore::open(&database_path).expect("open core");
        let project_id = core
            .open_local_project(&project_path)
            .expect("open project");
        let reference = core
            .load_or_prepare_conversation_reference(project_id)
            .expect("v1 reference");
        let first = StableRuntimeIdentity {
            authority: "authority-a".to_owned(),
            principal: "principal".to_owned(),
            lineage: "lineage".to_owned(),
            profile_id: "profile".to_owned(),
            schema_hash: "11".repeat(32),
            capability_digest: "22".repeat(32),
            binding_digest: "33".repeat(32),
            launch_generation: 1,
        };
        let bound = core
            .bind_conversation_reference(project_id, reference, &first)
            .expect("bind reference");
        let key = format!("runtime.conversation.project.{project_id}");
        let before = {
            let store = core.store.lock().expect("store");
            store.get_setting(&key).expect("read").expect("reference")
        };
        let mut conflicting = first;
        conflicting.authority = "authority-b".to_owned();

        let error = core
            .bind_conversation_reference(project_id, bound, &conflicting)
            .expect_err("identity conflict");
        assert_eq!(error.to_string(), "runtime_identity_conflict");
        assert_eq!(
            core.runtime_availability().expect("state"),
            RuntimeAvailability::Fatal
        );
        let after = {
            let store = core.store.lock().expect("store");
            store.get_setting(&key).expect("read").expect("reference")
        };
        assert_eq!(after.as_bytes(), before.as_bytes());
    }
