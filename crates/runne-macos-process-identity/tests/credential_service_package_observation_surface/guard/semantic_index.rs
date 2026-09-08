use std::collections::HashMap;
use std::path::PathBuf;

use super::ProductionSnapshot;
use super::source_edge_macros::{AttributeKind, AttributeResolution, MacroResolution};
use super::source_model::{
    BodyId, CanonicalTarget, OpaqueSourceMacroSite, PackageId, ScopeId, SourceId, SourceOrigin,
    SyntaxId, TargetId, TypeDefId, ValueDefId,
};
use super::symbols::{BodyRecord, ModuleRecord, SyntaxContext, TypeRecord, ValueRecord};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Resolution<T> {
    Exact(T),
    Ambiguous(Vec<T>),
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PathOrigin {
    CanonicalTarget,
    Local,
    ExternalOpaque,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IndexError {
    pub(super) source: Option<SourceId>,
    pub(super) reason: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct NodeAddress {
    pub(super) kind: u8,
    pub(super) address: usize,
}

#[derive(Clone)]
pub(super) struct IndexedItem {
    pub(super) source: SourceId,
    pub(super) syntax: SyntaxId,
    pub(super) scope: ScopeId,
    pub(super) item: syn::Item,
}

pub(super) struct SemanticIndex {
    pub(super) target: CanonicalTarget,
    pub(super) modules: Vec<ModuleRecord>,
    pub(super) items: Vec<IndexedItem>,
    pub(super) types: Vec<TypeRecord>,
    pub(super) values: Vec<ValueRecord>,
    pub(super) bodies: Vec<BodyRecord>,
    pub(super) node_contexts: HashMap<NodeAddress, SyntaxContext>,
    pub(super) scope_parents: HashMap<ScopeId, ScopeId>,
    pub(super) macros: super::source_edge_macros::MacroDefinitions,
    pub(super) imports: Vec<super::semantic_index_imports::ImportRecord>,
    pub(super) source_paths: HashMap<SourceId, PathBuf>,
    pub(super) source_origins: HashMap<SourceId, SourceOrigin>,
    pub(super) opaque_source_macros: Vec<OpaqueSourceMacroSite>,
    pub(super) modules_by_scope: HashMap<ScopeId, usize>,
    pub(super) modules_by_path: HashMap<(PackageId, TargetId, Vec<String>), usize>,
    pub(super) types_by_id: HashMap<TypeDefId, usize>,
    pub(super) values_by_id: HashMap<ValueDefId, usize>,
    pub(super) types_by_scope_name: HashMap<(ScopeId, String), Vec<TypeDefId>>,
    pub(super) values_by_scope_name: HashMap<(ScopeId, String), Vec<ValueDefId>>,
    pub(super) values_by_owner_name: HashMap<(TypeDefId, String), Vec<ValueDefId>>,
}

impl SemanticIndex {
    pub(super) fn build(snapshot: &ProductionSnapshot) -> Result<Self, IndexError> {
        super::semantic_index_build::build(snapshot)
    }

    pub(super) fn types(&self) -> impl Iterator<Item = &TypeRecord> {
        self.types.iter()
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &ValueRecord> {
        self.values.iter()
    }

    pub(super) fn bodies(&self) -> impl Iterator<Item = &BodyRecord> {
        self.bodies.iter()
    }

    pub(super) fn type_record(&self, id: TypeDefId) -> Option<&TypeRecord> {
        self.types_by_id.get(&id).map(|index| &self.types[*index])
    }

    pub(super) fn value_record(&self, id: ValueDefId) -> Option<&ValueRecord> {
        self.values_by_id.get(&id).map(|index| &self.values[*index])
    }

    pub(super) fn body_record(&self, id: BodyId) -> Option<&BodyRecord> {
        self.bodies.iter().find(|record| record.id == id)
    }

    pub(super) fn resolve_type(&self, scope: ScopeId, path: &syn::Path) -> Resolution<TypeDefId> {
        super::semantic_index_resolve::resolve_type(self, self.module_scope(scope), path)
    }

    pub(super) fn resolve_value(&self, scope: ScopeId, path: &syn::Path) -> Resolution<ValueDefId> {
        super::semantic_index_resolve::resolve_value(self, self.module_scope(scope), path)
    }

    pub(super) fn canonical_type(&self, id: TypeDefId) -> Resolution<TypeDefId> {
        super::semantic_index_resolve::canonical_type(self, id, &mut Vec::new())
    }

    pub(super) fn path_origin(&self, scope: ScopeId, path: &syn::Path) -> PathOrigin {
        super::semantic_index_origin::path_origin(self, self.module_scope(scope), path)
    }

    pub(super) fn source_origin(&self, source: SourceId) -> SourceOrigin {
        self.source_origins
            .get(&source)
            .copied()
            .unwrap_or(SourceOrigin::RustModule)
    }

    pub(super) fn resolve_macro(&self, scope: ScopeId, invocation: &syn::Macro) -> MacroResolution {
        super::semantic_index_macro::resolve_macro(self, self.module_scope(scope), invocation)
    }

    pub(super) fn resolve_generated_macro(
        &self,
        parent: &super::source_edge_macros::ResolvedMacroInvocation,
        generated_items: &[syn::Item],
        invocation: &syn::Macro,
    ) -> MacroResolution {
        super::semantic_index_macro::resolve_generated_macro(
            self,
            parent,
            generated_items,
            invocation,
        )
    }

    pub(super) fn resolve_pattern_macro(
        &self,
        parent: &super::source_edge_macros::ResolvedMacroInvocation,
        invocation: &syn::Macro,
    ) -> MacroResolution {
        self.macros.resolve_pattern_expansion(parent, invocation)
    }

    pub(super) fn classify_attribute(
        &self,
        scope: ScopeId,
        path: &syn::Path,
        kind: AttributeKind,
    ) -> AttributeResolution {
        super::semantic_index_macro::classify_attribute(self, self.module_scope(scope), path, kind)
    }

    pub(super) fn block_context(&self, node: &syn::Block) -> Option<SyntaxContext> {
        self.context(1, node)
    }

    pub(super) fn expr_context(&self, node: &syn::Expr) -> Option<SyntaxContext> {
        self.context(3, node)
    }

    fn context<T>(&self, kind: u8, node: &T) -> Option<SyntaxContext> {
        self.node_contexts
            .get(&NodeAddress {
                kind,
                address: std::ptr::from_ref(node).addr(),
            })
            .copied()
    }

    fn module_scope(&self, mut scope: ScopeId) -> ScopeId {
        while !self.modules_by_scope.contains_key(&scope) {
            let Some(parent) = self.scope_parents.get(&scope).copied() else {
                break;
            };
            scope = parent;
        }
        scope
    }

    pub(super) fn module(&self, scope: ScopeId) -> Option<&ModuleRecord> {
        self.modules_by_scope
            .get(&scope)
            .map(|index| &self.modules[*index])
    }

    pub(super) fn module_at(
        &self,
        package: PackageId,
        target: TargetId,
        path: &[String],
    ) -> Option<&ModuleRecord> {
        self.modules_by_path
            .get(&(package, target, path.to_vec()))
            .map(|index| &self.modules[*index])
    }

    pub(super) fn type_ids(&self, scope: ScopeId, name: &str) -> &[TypeDefId] {
        self.types_by_scope_name
            .get(&(scope, name.to_owned()))
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn value_ids(&self, scope: ScopeId, name: &str) -> &[ValueDefId] {
        self.values_by_scope_name
            .get(&(scope, name.to_owned()))
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn associated_value_ids(&self, owner: TypeDefId, name: &str) -> &[ValueDefId] {
        self.values_by_owner_name
            .get(&(owner, name.to_owned()))
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn rebuild_lookups(&mut self) {
        self.modules_by_scope = self
            .modules
            .iter()
            .enumerate()
            .map(|(index, module)| (module.scope, index))
            .collect();
        self.modules_by_path = self
            .modules
            .iter()
            .enumerate()
            .map(|(index, module)| ((module.package, module.target, module.path.clone()), index))
            .collect();
        self.types_by_id = self
            .types
            .iter()
            .enumerate()
            .map(|(index, record)| (record.id, index))
            .collect();
        self.values_by_id = self
            .values
            .iter()
            .enumerate()
            .map(|(index, record)| (record.id, index))
            .collect();
        self.types_by_scope_name.clear();
        for record in &self.types {
            self.types_by_scope_name
                .entry((record.scope, record.name.clone()))
                .or_default()
                .push(record.id);
        }
        self.values_by_scope_name.clear();
        self.values_by_owner_name.clear();
        for record in &self.values {
            self.values_by_scope_name
                .entry((record.scope, record.name.clone()))
                .or_default()
                .push(record.id);
            if let Some(owner) = record.owner {
                self.values_by_owner_name
                    .entry((owner, record.name.clone()))
                    .or_default()
                    .push(record.id);
            }
        }
    }

    pub(super) fn from_source(source: &str) -> Result<Self, IndexError> {
        super::semantic_index_build::from_source(source)
    }
}
