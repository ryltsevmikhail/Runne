//! C exports are association inputs. Real S-owned Child handles remain separate.
use super::clock::Deadline;
use super::io::{HeldRoot, ram_device};
use super::model::{CollectionKey, ContextRecord};
use super::process_view::{self, ProcessView};
use std::fs::DirBuilder;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;
use uuid::Uuid;

const CONTEXT_ENV: &str = "RUNNE_R05_CASE_CONTEXT_V1";
const CAP: usize = 16384;

fn export(name: &str) -> String {
    let value = std::env::var(name).expect("required C collection export");
    let cap = if name == CONTEXT_ENV { CAP } else { 4096 };
    assert!(value.len() <= cap && value.is_ascii());
    value
}

pub(super) struct CollectionContext {
    pub key: CollectionKey,
    pub root: HeldRoot,
    pub supervisor: ProcessView,
}

impl CollectionContext {
    pub(super) fn supervisor(deadline: Deadline) -> Self {
        assert!(
            std::env::var_os(CONTEXT_ENV).is_none(),
            "only S creates context"
        );
        let key = CollectionKey {
            source: export("RUNNE_R05_COLLECTION_SOURCE"),
            artifact: export("RUNNE_R05_COLLECTION_ARTIFACT"),
            nonce: export("RUNNE_R05_COLLECTION_RUN"),
        };
        key.validate();
        let root = HeldRoot::open(
            PathBuf::from(export("RUNNE_R05_COLLECTION_ROOT")),
            "runne-r05-collector-",
            deadline,
        );
        assert_eq!(root.identity.device, ram_device(deadline));
        assert_eq!(root.file.metadata().unwrap().nlink(), 2);
        assert!(std::fs::read_dir(&root.path).unwrap().next().is_none());
        let supervisor = process_view::current(deadline);
        assert_ne!(supervisor.process, supervisor.parent);
        root.check(deadline);
        Self {
            key,
            root,
            supervisor,
        }
    }
}

pub(super) struct CaseContext {
    pub record: ContextRecord,
    pub root: HeldRoot,
    pub collection_root: HeldRoot,
    pub deadline: Deadline,
}

impl CaseContext {
    pub(super) fn new_supervisor() -> Self {
        let deadline = Deadline::new_supervisor();
        let collection = CollectionContext::supervisor(deadline);
        let scenario = Uuid::now_v7();
        let path = PathBuf::from(format!("/dev/shm/runne-r05-case-{scenario}"));
        // Exclusive new directory. Never reuse a previous scenario or clean on failure.
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        let root = HeldRoot::open(path, "runne-r05-case-", deadline);
        let view = collection.supervisor;
        let record = ContextRecord {
            version: 1,
            collection: collection.key,
            scenario,
            collector: view.parent,
            supervisor: view.process,
            collection_root: collection.root.path.to_str().unwrap().to_owned(),
            collection_identity: collection.root.identity.clone(),
            case_root: root.path.to_str().unwrap().to_owned(),
            case_identity: root.identity.clone(),
            pid_namespace: view.pid_namespace,
            mount_namespace: view.mount_namespace,
            membership: view.membership,
            deadline_ns: deadline.0,
        };
        record.validate();
        Self {
            record,
            root,
            collection_root: collection.root,
            deadline,
        }
    }

    pub(super) fn inherit_child() -> Self {
        let text = export(CONTEXT_ENV);
        assert!(text.len() <= CAP);
        let record: ContextRecord = serde_json::from_str(&text).unwrap();
        record.validate();
        let deadline = Deadline::inherited(record.deadline_ns);
        let root = HeldRoot::open(
            PathBuf::from(&record.case_root),
            "runne-r05-case-",
            deadline,
        );
        let collection_root = HeldRoot::open(
            PathBuf::from(&record.collection_root),
            "runne-r05-collector-",
            deadline,
        );
        assert_eq!(root.identity, record.case_identity);
        assert_eq!(collection_root.identity, record.collection_identity);
        assert_eq!(root.identity.device, ram_device(deadline));
        let value = Self {
            record,
            root,
            collection_root,
            deadline,
        };
        value.check_child();
        value
    }

    pub(super) fn check_child(&self) {
        self.check_roots();
        let actual = process_view::current(self.deadline);
        assert_eq!(actual.parent, self.record.supervisor);
        assert!(![self.record.collector, self.record.supervisor].contains(&actual.process));
        assert_eq!(actual.pid_namespace, self.record.pid_namespace);
        assert_eq!(actual.mount_namespace, self.record.mount_namespace);
        assert_eq!(actual.membership, self.record.membership);
        assert_eq!(
            export("RUNNE_R05_COLLECTION_SOURCE"),
            self.record.collection.source
        );
        assert_eq!(
            export("RUNNE_R05_COLLECTION_ARTIFACT"),
            self.record.collection.artifact
        );
        assert_eq!(
            export("RUNNE_R05_COLLECTION_RUN"),
            self.record.collection.nonce
        );
        assert_eq!(
            export("RUNNE_R05_COLLECTION_ROOT"),
            self.record.collection_root
        );
        self.deadline.check();
    }

    pub(super) fn check_roots(&self) {
        self.record.validate();
        assert_eq!(self.record.deadline_ns, self.deadline.0);
        self.root.check(self.deadline);
        self.collection_root.check(self.deadline);
        assert_eq!(self.collection_root.file.metadata().unwrap().nlink(), 2);
    }

    pub(super) fn command(&self, command: &mut Command) {
        self.check_roots();
        let actual = process_view::current(self.deadline);
        assert_eq!(
            (actual.process, actual.parent),
            (self.record.supervisor, self.record.collector)
        );
        assert_eq!(actual.pid_namespace, self.record.pid_namespace);
        assert_eq!(actual.mount_namespace, self.record.mount_namespace);
        assert_eq!(actual.membership, self.record.membership);
        let text = serde_json::to_string(&self.record).unwrap();
        assert!(text.len() <= CAP && text.is_ascii());
        command
            .env(CONTEXT_ENV, text)
            .env("RUNNE_R05_COLLECTION_ROOT", &self.record.collection_root)
            .env(
                "RUNNE_R05_COLLECTION_SOURCE",
                &self.record.collection.source,
            )
            .env(
                "RUNNE_R05_COLLECTION_ARTIFACT",
                &self.record.collection.artifact,
            )
            .env("RUNNE_R05_COLLECTION_RUN", &self.record.collection.nonce);
        self.deadline.check();
    }

    pub(super) fn observer_deadline(&self) -> Instant {
        // Sample Instant BEFORE boot remaining to avoid extending the shared budget.
        let start = Instant::now();
        let remaining = self.deadline.remaining();
        let end = start.checked_add(remaining).unwrap();
        self.deadline.check();
        end
    }
}
