use std::collections::HashMap;

use super::ProductionSnapshot;
use super::semantic_index::{IndexError, IndexedItem, SemanticIndex};
use super::semantic_index_imports::ImportRecord;
use super::source_model::{
    CanonicalTarget, DefId, ModuleId, Namespace, PackageId, ScopeId, SourceId, SyntaxId, TargetId,
    TypeDefId, ValueDefId,
};
use super::symbols::{
    BodyRecord, CanonicalMethod, ModuleRecord, TypeKind, TypeRecord, ValueKind, ValueRecord,
};

pub(super) fn build(snapshot: &ProductionSnapshot) -> Result<SemanticIndex, IndexError> {
    let mut builder = Builder::new(snapshot);
    super::semantic_index_graph::collect_modules(&mut builder)?;
    builder.collect_items()?;
    super::semantic_index_values::collect_values(&mut builder);
    let mut index = builder.finish();
    index.rebuild_lookups();
    super::semantic_index_context::register_body_contexts(&mut index);
    Ok(index)
}

pub(super) fn from_source(source: &str) -> Result<SemanticIndex, IndexError> {
    super::semantic_index_fixture::from_source(source)
}

pub(super) struct Builder<'a> {
    pub(super) snapshot: &'a ProductionSnapshot,
    pub(super) target: CanonicalTarget,
    pub(super) modules: Vec<ModuleRecord>,
    pub(super) items: Vec<IndexedItem>,
    pub(super) types: Vec<TypeRecord>,
    pub(super) values: Vec<ValueRecord>,
    pub(super) bodies: Vec<BodyRecord>,
    pub(super) imports: Vec<ImportRecord>,
    pub(super) next_syntax: u32,
}

impl<'a> Builder<'a> {
    fn new(snapshot: &'a ProductionSnapshot) -> Self {
        let target = CanonicalTarget::default();
        let canonical = TypeDefId(DefId {
            package: PackageId(u32::MAX),
            target: TargetId(u32::MAX),
            module: ModuleId(u32::MAX),
            namespace: Namespace::Type,
            syntax: SyntaxId(0),
        });
        let synthetic_value = |syntax, name: String, canonical_method| ValueRecord {
            id: ValueDefId(DefId {
                package: PackageId(u32::MAX),
                target: TargetId(u32::MAX),
                module: ModuleId(u32::MAX),
                namespace: Namespace::Value,
                syntax: SyntaxId(syntax),
            }),
            name,
            scope: ScopeId(u32::MAX),
            owner: Some(canonical),
            canonical_method: Some(canonical_method),
            kind: ValueKind::Function { body: None },
        };
        Self {
            snapshot,
            types: vec![TypeRecord {
                id: canonical,
                name: target.type_path.last().unwrap().clone(),
                scope: ScopeId(u32::MAX),
                source: SourceId(u32::MAX),
                kind: TypeKind::CanonicalTarget,
            }],
            values: vec![
                synthetic_value(1, target.capture_method.clone(), CanonicalMethod::Capture),
                synthetic_value(2, target.verify_method.clone(), CanonicalMethod::Verify),
            ],
            target,
            modules: Vec::new(),
            items: Vec::new(),
            bodies: Vec::new(),
            imports: Vec::new(),
            next_syntax: 0,
        }
    }

    pub(super) const fn syntax(&mut self) -> SyntaxId {
        let id = SyntaxId(self.next_syntax);
        self.next_syntax += 1;
        id
    }

    pub(super) fn def_id(&self, scope: ScopeId, namespace: Namespace, syntax: SyntaxId) -> DefId {
        let module = self
            .modules
            .iter()
            .find(|module| module.scope == scope)
            .unwrap();
        DefId {
            package: module.package,
            target: module.target,
            module: module.id,
            namespace,
            syntax,
        }
    }

    fn finish(self) -> SemanticIndex {
        let opaque_source_macros = self
            .snapshot
            .graph
            .opaque_source_macros
            .iter()
            .flat_map(|opaque| {
                let sources = self
                    .snapshot
                    .graph
                    .nodes
                    .iter()
                    .filter(|node| node.canonical_path == opaque.from)
                    .map(|node| node.id)
                    .collect::<Vec<_>>();
                assert!(
                    !sources.is_empty(),
                    "opaque macro source omitted from immutable snapshot: {}",
                    opaque.from.display()
                );
                sources
                    .into_iter()
                    .map(move |source| super::source_model::OpaqueSourceMacroSite {
                        source,
                        macro_path: opaque.macro_path.clone(),
                    })
            })
            .collect();
        SemanticIndex {
            target: self.target,
            modules: self.modules,
            items: self.items,
            types: self.types,
            values: self.values,
            bodies: self.bodies,
            node_contexts: HashMap::new(),
            scope_parents: HashMap::new(),
            macros: self.snapshot.macros.clone(),
            imports: self.imports,
            source_paths: self
                .snapshot
                .graph
                .nodes
                .iter()
                .map(|node| (node.id, node.canonical_path.clone()))
                .collect(),
            source_origins: self
                .snapshot
                .graph
                .nodes
                .iter()
                .map(|node| {
                    (
                        node.id,
                        super::semantic_index_fixture::effective_origin(&node.bytes, node.origin),
                    )
                })
                .collect(),
            opaque_source_macros,
            modules_by_scope: HashMap::new(),
            modules_by_path: HashMap::new(),
            types_by_id: HashMap::new(),
            values_by_id: HashMap::new(),
            types_by_scope_name: HashMap::new(),
            values_by_scope_name: HashMap::new(),
            values_by_owner_name: HashMap::new(),
        }
    }
}
