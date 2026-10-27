//! Closed scenario association data, never a process or permission capability.
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CollectionKey {
    pub source: String,
    pub artifact: String,
    pub nonce: String,
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

impl CollectionKey {
    pub(super) fn validate(&self) {
        assert!(lower_hex(&self.source, 64));
        assert!(lower_hex(&self.artifact, 64));
        assert!(lower_hex(&self.nonce, 32));
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

impl RootIdentity {
    pub(super) fn validate(&self) {
        assert_ne!(self.inode, 0);
        assert_eq!((self.uid, self.gid, self.mode), (1000, 1000, 0o40700));
    }
}

pub(super) fn pid(value: u32) {
    assert!(value > 1 && value <= i32::MAX as u32);
}

pub(super) fn root_name(path: &Path, prefix: &str) {
    assert_eq!(path.parent(), Some(Path::new("/dev/shm")));
    let name = path.file_name().unwrap().to_str().unwrap();
    let suffix = name.strip_prefix(prefix).expect("closed guest root prefix");
    assert!(!suffix.is_empty() && suffix.len() <= 64);
    assert!(
        suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    );
    // Reject paths whose spelling normalizes to a different pathname.
    assert_eq!(path.to_str().unwrap(), format!("/dev/shm/{name}"));
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContextRecord {
    pub version: u32,
    pub collection: CollectionKey,
    #[serde(with = "super::uuid_text")]
    pub scenario: Uuid,
    pub collector: u32,
    pub supervisor: u32,
    pub collection_root: String,
    pub collection_identity: RootIdentity,
    pub case_root: String,
    pub case_identity: RootIdentity,
    pub pid_namespace: String,
    pub mount_namespace: String,
    pub membership: String,
    pub deadline_ns: u64,
}

fn namespace(value: &str, prefix: &str) {
    let number = value
        .strip_prefix(prefix)
        .unwrap()
        .strip_suffix(']')
        .unwrap();
    assert!(!number.is_empty() && number.len() <= 20);
    assert!(!number.starts_with('0') && number.bytes().all(|b| b.is_ascii_digit()));
    assert!(number.parse::<u64>().unwrap() > 0);
}

impl ContextRecord {
    pub(super) fn validate(&self) {
        assert_eq!(self.version, 1);
        self.collection.validate();
        assert_eq!(self.scenario.get_version_num(), 7);
        assert_eq!(self.scenario.as_bytes()[8] & 0xc0, 0x80);
        pid(self.collector);
        pid(self.supervisor);
        assert_ne!(self.collector, self.supervisor);
        root_name(Path::new(&self.collection_root), "runne-r05-collector-");
        root_name(Path::new(&self.case_root), "runne-r05-case-");
        assert_eq!(
            self.case_root,
            format!("/dev/shm/runne-r05-case-{}", self.scenario)
        );
        self.collection_identity.validate();
        self.case_identity.validate();
        assert_eq!(self.collection_identity.device, self.case_identity.device);
        assert_ne!(self.collection_identity.inode, self.case_identity.inode);
        namespace(&self.pid_namespace, "pid:[");
        namespace(&self.mount_namespace, "mnt:[");
        // Use the accepted unified-path parser rather than a second grammar.
        assert_eq!(
            super::association::membership(&format!("0::{}\n", self.membership)),
            self.membership
        );
        assert_ne!(self.deadline_ns, 0);
    }
}
