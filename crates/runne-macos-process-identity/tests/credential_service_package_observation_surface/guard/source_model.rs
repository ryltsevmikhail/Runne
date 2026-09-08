use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct PackageId(pub(super) u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct TargetId(pub(super) u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct SourceId(pub(super) u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ModuleId(pub(super) u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct SyntaxId(pub(super) u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ScopeId(pub(super) u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct BodyId(pub(super) u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct BindingId {
    pub(super) body: BodyId,
    pub(super) scope: ScopeId,
    pub(super) ordinal: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum Namespace {
    Type,
    Value,
    Macro,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct DefId {
    pub(super) package: PackageId,
    pub(super) target: TargetId,
    pub(super) module: ModuleId,
    pub(super) namespace: Namespace,
    pub(super) syntax: SyntaxId,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct TypeDefId(pub(super) DefId);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ValueDefId(pub(super) DefId);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct MacroDefId(pub(super) DefId);

#[derive(Clone, Debug)]
pub(super) struct CrateUnit {
    pub(super) package: PackageId,
    pub(super) target: TargetId,
    pub(super) crate_name: String,
    pub(super) root: SourceId,
}

#[derive(Clone, Debug)]
pub(super) struct SourceNode {
    pub(super) id: SourceId,
    pub(super) package: PackageId,
    pub(super) target: TargetId,
    pub(super) canonical_path: PathBuf,
    pub(super) bytes: String,
    pub(super) origin: SourceOrigin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceOrigin {
    RustModule,
    ResolvedInclude,
    ContextDependentInclude,
    OpaqueMacroInclude,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum SourceEdgeKind {
    Module { declared_name: String },
    Include { expansion_site: SyntaxId },
}

#[derive(Clone, Debug)]
pub(super) struct SourceEdgeRecord {
    pub(super) from: PathBuf,
    pub(super) from_module_scope: Vec<String>,
    pub(super) target: PathBuf,
    pub(super) kind: SourceEdgeKind,
    pub(super) origin: SourceOrigin,
}

#[derive(Clone, Debug)]
pub(super) struct SourceEdge {
    pub(super) from: SourceId,
    pub(super) from_module_scope: Vec<String>,
    pub(super) target: SourceId,
    pub(super) kind: SourceEdgeKind,
}

#[derive(Clone, Debug)]
pub(super) struct OpaqueSourceMacro {
    pub(super) from: PathBuf,
    pub(super) macro_path: String,
}

#[derive(Clone, Debug)]
pub(super) struct OpaqueSourceMacroSite {
    pub(super) source: SourceId,
    pub(super) macro_path: String,
}

#[derive(Clone, Debug, Default)]
pub(super) struct SourceGraph {
    pub(super) crates: Vec<CrateUnit>,
    pub(super) nodes: Vec<SourceNode>,
    pub(super) edges: Vec<SourceEdge>,
    pub(super) opaque_source_macros: Vec<OpaqueSourceMacro>,
}

impl SourceGraph {
    pub(super) fn node(&self, id: SourceId) -> Option<&SourceNode> {
        self.nodes.iter().find(|node| node.id == id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CanonicalTarget {
    pub(super) crate_name: String,
    pub(super) type_path: Vec<String>,
    pub(super) capture_method: String,
    pub(super) verify_method: String,
}

impl Default for CanonicalTarget {
    fn default() -> Self {
        Self {
            crate_name: "runne_macos_process_identity".into(),
            type_path: vec!["MacOsPendingCredentialServicePackageObservationV1".into()],
            capture_method: "capture_current".into(),
            verify_method: "verify_exact".into(),
        }
    }
}
