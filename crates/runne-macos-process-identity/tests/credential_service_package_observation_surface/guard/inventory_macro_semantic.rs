use std::path::{Path, PathBuf};

use super::inventory_macro_bindings::{ResolvedMacroArm, selected_raw_arms};
use super::inventory_macro_resolution::{MacroAlias, MacroDefinition, MacroDefinitions};
use super::inventory_macro_scope::{local_aliases, local_definitions};
use super::source_model::{
    DefId, MacroDefId, ModuleId, Namespace, PackageId, ScopeId, SyntaxId, TargetId,
};

#[path = "inventory_macro_semantic/generated.rs"]
mod generated;
#[path = "inventory_macro_semantic/pattern_expansion.rs"]
mod pattern_expansion;

pub(super) const DEFINITION_CRATE_MARKER: &str = "__runne_definition_crate";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum UnresolvedReason {
    MissingScope,
    MissingDefinition,
    AmbiguousDefinition,
    UnsupportedArm,
    RecursiveExpansion,
}

#[derive(Clone)]
pub(super) struct ResolvedMacroInvocation {
    pub(super) definition: MacroDefId,
    pub(super) definition_source: PathBuf,
    pub(super) definition_scope: Vec<String>,
    pub(super) invocation_source: PathBuf,
    pub(super) invocation_scope: Vec<String>,
    pub(super) invocation_position: u32,
    pub(super) analysis_scope: Option<ScopeId>,
    pub(super) selected_arms: Vec<ResolvedMacroArm>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BuiltinMacro {
    Matches,
    Panic,
    Unimplemented,
    Unreachable,
    Todo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AttributeKind {
    Inert,
    Derive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BuiltinAttribute {
    Inert,
    Derive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AttributeResolution {
    Builtin(BuiltinAttribute),
    Opaque,
}

pub(super) enum MacroResolution {
    Workspace(ResolvedMacroInvocation),
    Builtin(BuiltinMacro),
    External,
    Unresolved(UnresolvedReason),
}

impl MacroDefinitions {
    pub(super) fn resolve_invocation(
        &self,
        source: &Path,
        scope: &[String],
        path: &syn::Path,
        tokens: &proc_macro2::TokenStream,
    ) -> MacroResolution {
        let Some((target_scope, name)) =
            super::inventory_macro_scope::macro_path_scope(scope, path)
        else {
            if is_external_path(path) {
                return MacroResolution::External;
            }
            return MacroResolution::Unresolved(UnresolvedReason::MissingDefinition);
        };
        let Some(source_position) = super::inventory_macro_collection::invocation_position(
            self, source, scope, path, tokens,
        ) else {
            return MacroResolution::Unresolved(UnresolvedReason::MissingDefinition);
        };
        match self.resolve_semantic_definition(
            source,
            &target_scope,
            &name,
            source_position,
            path.segments.len() > 1,
            &mut Vec::new(),
        ) {
            Ok(Some(definition)) => {
                Self::resolve_known_definition(definition, tokens, source, scope, source_position)
            }
            Ok(None)
                if builtin_macro(path).is_some()
                    && builtin_is_unshadowed(self, source, scope, &name, source_position) =>
            {
                MacroResolution::Builtin(builtin_macro(path).unwrap())
            }
            Ok(None) if is_external_path(path) => MacroResolution::External,
            Ok(None) => MacroResolution::Unresolved(UnresolvedReason::MissingDefinition),
            Err(reason) => MacroResolution::Unresolved(reason),
        }
    }

    pub(super) fn resolve_known_definition(
        definition: &MacroDefinition,
        tokens: &proc_macro2::TokenStream,
        invocation_source: &Path,
        invocation_scope: &[String],
        invocation_position: u32,
    ) -> MacroResolution {
        match selected_raw_arms(&definition.arms, tokens) {
            Ok(selected_arms) => MacroResolution::Workspace(ResolvedMacroInvocation {
                definition: macro_id(definition),
                definition_source: definition.source.clone(),
                definition_scope: definition.scope.clone(),
                invocation_source: invocation_source.to_path_buf(),
                invocation_scope: invocation_scope.to_vec(),
                invocation_position,
                analysis_scope: None,
                selected_arms,
            }),
            Err(()) => MacroResolution::Unresolved(UnresolvedReason::UnsupportedArm),
        }
    }

    pub(super) fn resolve_generated_invocation(
        &self,
        parent: &ResolvedMacroInvocation,
        items: &[syn::Item],
        invocation: &syn::Macro,
    ) -> MacroResolution {
        generated::resolve(self, parent, items, invocation)
    }

    fn resolve_semantic_definition<'a>(
        &'a self,
        source: &Path,
        scope: &[String],
        name: &str,
        source_position: u32,
        exact_scope: bool,
        stack: &mut Vec<(PathBuf, Vec<String>, String)>,
    ) -> Result<Option<&'a MacroDefinition>, UnresolvedReason> {
        let key = (source.to_path_buf(), scope.to_vec(), name.to_owned());
        if stack.contains(&key) {
            return Err(UnresolvedReason::RecursiveExpansion);
        }
        stack.push(key);
        let definitions =
            local_definitions(self, source, scope, name, source_position, exact_scope);
        let aliases = local_aliases(self, source, scope, name, source_position, exact_scope);
        let result = if !definitions.is_empty() {
            nearest_definition(&definitions)
        } else if !aliases.is_empty() {
            let alias = nearest_alias(&aliases)?;
            self.resolve_semantic_alias(alias, stack)
        } else {
            let nearby = if exact_scope {
                Vec::new()
            } else {
                super::inventory_macro_scope::nearby_external_definitions(self, source, name)
            };
            match nearby.as_slice() {
                [] => Ok(None),
                [definition] => Ok(Some(*definition)),
                _ => Err(UnresolvedReason::AmbiguousDefinition),
            }
        };
        stack.pop();
        result
    }

    fn resolve_semantic_alias<'a>(
        &'a self,
        alias: &MacroAlias,
        stack: &mut Vec<(PathBuf, Vec<String>, String)>,
    ) -> Result<Option<&'a MacroDefinition>, UnresolvedReason> {
        if alias.target == ["std", "include"] {
            return Ok(None);
        }
        let (scope, name) =
            super::inventory_macro_scope::alias_target_scope(&alias.scope, &alias.target);
        self.resolve_semantic_definition(
            &alias.source,
            &scope,
            &name,
            alias.source_position,
            true,
            stack,
        )
    }
}

fn builtin_macro(path: &syn::Path) -> Option<BuiltinMacro> {
    if path.leading_colon.is_some() || path.segments.len() != 1 {
        return None;
    }
    match path.segments.first()?.ident.to_string().as_str() {
        "matches" => Some(BuiltinMacro::Matches),
        "panic" => Some(BuiltinMacro::Panic),
        "unimplemented" => Some(BuiltinMacro::Unimplemented),
        "unreachable" => Some(BuiltinMacro::Unreachable),
        "todo" => Some(BuiltinMacro::Todo),
        _ => None,
    }
}

fn builtin_is_unshadowed(
    definitions: &MacroDefinitions,
    source: &Path,
    scope: &[String],
    name: &str,
    source_position: u32,
) -> bool {
    local_definitions(definitions, source, scope, name, source_position, false).is_empty()
        && local_aliases(definitions, source, scope, name, source_position, false).is_empty()
        && super::inventory_macro_scope::nearby_external_definitions(definitions, source, name)
            .is_empty()
}

fn nearest_definition<'a>(
    candidates: &[&'a MacroDefinition],
) -> Result<Option<&'a MacroDefinition>, UnresolvedReason> {
    let depth = candidates
        .iter()
        .map(|item| item.scope.len())
        .max()
        .unwrap();
    let nearest = candidates
        .iter()
        .filter(|item| item.scope.len() == depth)
        .copied()
        .collect::<Vec<_>>();
    match nearest.as_slice() {
        [definition] => Ok(Some(*definition)),
        _ => Err(UnresolvedReason::AmbiguousDefinition),
    }
}

fn nearest_alias<'a>(candidates: &[&'a MacroAlias]) -> Result<&'a MacroAlias, UnresolvedReason> {
    let depth = candidates
        .iter()
        .map(|item| item.scope.len())
        .max()
        .unwrap();
    let nearest = candidates
        .iter()
        .filter(|item| item.scope.len() == depth)
        .copied()
        .collect::<Vec<_>>();
    match nearest.as_slice() {
        [alias] => Ok(*alias),
        _ => Err(UnresolvedReason::AmbiguousDefinition),
    }
}

const fn macro_id(definition: &MacroDefinition) -> MacroDefId {
    let ordinal = definition.ordinal;
    MacroDefId(DefId {
        package: PackageId(u32::MAX),
        target: TargetId(u32::MAX),
        module: ModuleId(ordinal),
        namespace: Namespace::Macro,
        syntax: SyntaxId(ordinal),
    })
}

fn is_external_path(path: &syn::Path) -> bool {
    path.leading_colon.is_some()
        || path.segments.len() > 1
            && !matches!(
                path.segments.first().map(|segment| segment.ident.to_string()),
                Some(root)
                    if ["crate", "self", "super", DEFINITION_CRATE_MARKER]
                        .contains(&root.as_str())
            )
}
