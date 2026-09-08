use super::cfg_projection;
use super::semantic_index::{IndexError, IndexedItem};
use super::semantic_index_build::Builder;
use super::semantic_index_imports::{extern_crate_record, use_records};
use super::source_model::{ModuleId, Namespace, ScopeId, SourceId, SyntaxId, TypeDefId};
use super::symbols::{ModuleRecord, TypeKind, TypeRecord, fields};

impl Builder<'_> {
    pub(super) fn collect_items(&mut self) -> Result<(), IndexError> {
        let modules = self.modules.clone();
        for module in modules {
            let Some(node) = self.snapshot.graph.node(module.source) else {
                continue;
            };
            let file = super::semantic_index_fixture::parse_source_fragment(&node.bytes).map_err(
                |error| IndexError {
                    source: Some(node.id),
                    reason: format!("production source must parse: {error}"),
                },
            )?;
            self.collect_item_slice(module.source, module.scope, &file.items);
        }
        Ok(())
    }

    fn collect_item_slice(&mut self, source: SourceId, scope: ScopeId, items: &[syn::Item]) {
        for item in items {
            if !cfg_projection::is_production(item_attributes(item)) {
                continue;
            }
            let syntax = self.syntax();
            self.items.push(IndexedItem {
                source,
                syntax,
                scope,
                item: item.clone(),
            });
            match item {
                syn::Item::Use(item) => self.imports.extend(use_records(scope, &item.tree)),
                syn::Item::ExternCrate(item) => {
                    self.imports.extend(extern_crate_record(scope, item));
                }
                syn::Item::Struct(item) => self.add_type(
                    source,
                    scope,
                    syntax,
                    &item.ident,
                    TypeKind::Struct(fields(&item.fields)),
                ),
                syn::Item::Enum(item) => {
                    let variants = item
                        .variants
                        .iter()
                        .filter(|variant| cfg_projection::is_production(&variant.attrs))
                        .map(|variant| super::symbols::VariantRecord {
                            fields: fields(&variant.fields),
                        })
                        .collect();
                    self.add_type(source, scope, syntax, &item.ident, TypeKind::Enum(variants));
                }
                syn::Item::Union(item) => self.add_type(
                    source,
                    scope,
                    syntax,
                    &item.ident,
                    TypeKind::Union(fields(&syn::Fields::Named(item.fields.clone()))),
                ),
                syn::Item::Type(item) => self.add_type(
                    source,
                    scope,
                    syntax,
                    &item.ident,
                    TypeKind::Alias(item.ty.clone()),
                ),
                syn::Item::Mod(item) => self.collect_inline_module(source, scope, item),
                _ => {}
            }
        }
    }

    fn collect_inline_module(&mut self, source: SourceId, parent: ScopeId, item: &syn::ItemMod) {
        let Some((_, items)) = &item.content else {
            return;
        };
        let Some(parent_record) = self
            .modules
            .iter()
            .find(|module| module.scope == parent)
            .cloned()
        else {
            return;
        };
        let scope = ScopeId(u32::try_from(self.modules.len()).expect("module count exceeds u32"));
        let mut path = parent_record.path.clone();
        path.push(item.ident.to_string());
        let scope = if let Some(existing) = self.modules.iter_mut().find(|module| {
            module.package == parent_record.package
                && module.target == parent_record.target
                && module.path == path
        }) {
            existing.parent = Some(parent);
            existing.scope
        } else {
            self.modules.push(ModuleRecord {
                id: ModuleId(scope.0),
                package: parent_record.package,
                target: parent_record.target,
                scope,
                source,
                path,
                parent: Some(parent),
                children: std::collections::BTreeMap::default(),
            });
            scope
        };
        if let Some(record) = self
            .modules
            .iter_mut()
            .find(|module| module.scope == parent)
        {
            record.children.insert(item.ident.to_string(), scope);
        }
        self.collect_item_slice(source, scope, items);
    }

    fn add_type(
        &mut self,
        source: SourceId,
        scope: ScopeId,
        syntax: SyntaxId,
        name: &syn::Ident,
        mut kind: TypeKind,
    ) {
        if self.is_canonical_target(scope, &name.to_string()) {
            kind = TypeKind::CanonicalTarget;
        }
        self.types.push(TypeRecord {
            id: TypeDefId(self.def_id(scope, Namespace::Type, syntax)),
            name: name.to_string(),
            scope,
            source,
            kind,
        });
    }

    fn is_canonical_target(&self, scope: ScopeId, name: &str) -> bool {
        let Some(module) = self.modules.iter().find(|module| module.scope == scope) else {
            return false;
        };
        let Some(unit) = self
            .snapshot
            .graph
            .crates
            .iter()
            .find(|unit| unit.package == module.package && unit.target == module.target)
        else {
            return false;
        };
        unit.crate_name == self.target.crate_name
            && module.path == self.target.type_path[..self.target.type_path.len() - 1]
            && self
                .target
                .type_path
                .last()
                .is_some_and(|target| target == name)
    }
}

fn item_attributes(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        _ => &[],
    }
}
