// Grammar-aware locations from a VALID packet; never a permissive decoder.
use std::{collections::BTreeMap, ops::Range};
struct WireFixture {
    bytes: Vec<u8>,
    capture: Vec<u8>,
    digest: [u8; 32],
    row: CaptureContextRowV1,
    fields: BTreeMap<&'static str, Range<usize>>,
}
impl WireFixture {
    fn new(binding: &LocalCommandPermissionBindingV1) -> Self {
        let (capture, digest, row) = packet(binding);
        let bytes = wire::encode(&from_capture(binding, &capture, digest).unwrap()).unwrap();
        let mut fields = BTreeMap::new();
        let mut at = 0;
        fn mark(
            map: &mut BTreeMap<&'static str, Range<usize>>,
            at: &mut usize,
            name: &'static str,
            size: usize,
        ) {
            map.insert(name, *at..*at + size);
            *at += size;
        }
        macro_rules! field {
            ($name:literal, $size:expr) => {
                mark(&mut fields, &mut at, $name, $size)
            };
        }
        field!("context_version", 2);
        field!("capture_version", 1);
        field!("capture_digest", 32);
        field!("canonical_digest", 32);
        field!("source_version", 8);
        field!("command_version", 8);
        field!("preset_version", 2);
        field!("containment", 1);
        let posture = bytes[at];
        field!("filesystem", 1);
        if posture == 1 {
            let count = bytes[at];
            field!("root_count", 1);
            let start = at;
            for _ in 0..count {
                at += 32;
                let count = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap());
                at += 2;
                for _ in 0..count {
                    let len = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap());
                    at += 2 + usize::from(len);
                }
            }
            fields.insert("roots", start..at);
        }
        let rights = usize::from(bytes[at]);
        field!("rights_count", 1);
        field!("rights", rights);
        field!("network", 1);
        field!("coverage", 1);
        let children = bytes[at];
        field!("children", 1);
        if children == 1 {
            field!("depth", 2);
        }
        for name in ["operations", "bytes"] {
            let size = if bytes[at] == 1 { 9 } else { 1 };
            mark(&mut fields, &mut at, name, size);
        }
        field!("lifetime", 8);
        field!("protected", 32);
        field!("status", 1);
        field!("mask", 4);
        field!("epoch", 8);
        field!("revision", 8);
        field!("policy_version", 4);
        field!("policy_decisions", 6);
        field!("approval_expiry", 8);
        field!("relevant_digest", 32);
        field!("projection_version", 2);
        let projection = bytes[at];
        field!("projection_tag", 1);
        if projection == 1 {
            field!("evaluator_version", 2);
            field!("semantics_version", 2);
            field!("provided", 6);
            field!("decisions", 6);
            field!("semantics_digest", 32);
        } else {
            field!("unsupported_reason", 1);
        }
        assert_eq!(at, bytes.len(), "fixture consumes exact frozen grammar");
        Self {
            bytes,
            capture,
            digest,
            row,
            fields,
        }
    }
    fn replace(&self, field: &str, value: &[u8]) -> Vec<u8> {
        let mut bytes = self.bytes.clone();
        bytes.splice(self.fields[field].clone(), value.iter().copied());
        bytes
    }
    fn refuse(&self, field: &str, why: &str, bytes: &[u8], expected: ContextErrorV1) {
        let hash = wire::context_digest(bytes).unwrap();
        assert_eq!(
            wire::decode_checked(bytes, &hash, &self.capture, &self.digest, &self.row),
            Err(expected),
            "{field}: {why}"
        );
    }
}
fn bounded_binding(original: &LocalCommandPermissionBindingV1) -> LocalCommandPermissionBindingV1 {
    let mut scope = original.scope().clone();
    scope.containment = ContainmentStrategy::WorkspaceBoundV1;
    scope.filesystem.posture = FilesystemPosture::BoundedRoots(
        [FilesystemRoot::new(
            IntegrityDigest::from_bytes([9; 32]),
            vec!["z".into(), "a".into()],
        )
        .unwrap()]
        .into_iter()
        .collect(),
    );
    scope.children = ChildDelegationScope::MaxDepth(0);
    scope.budget = EffectBudget {
        max_operations: Some(0),
        max_bytes: Some(0),
    };
    rebuild(
        original,
        scope,
        original.closed_rules_snapshot(),
        PermissionMode::AskAlways,
        42,
        [0; 32],
    )
}
fn raw_root(identity: u8, components: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![identity; 32];
    bytes.extend(u16::try_from(components.len()).unwrap().to_be_bytes());
    for part in components {
        bytes.extend(u16::try_from(part.len()).unwrap().to_be_bytes());
        bytes.extend(part);
    }
    bytes
}
