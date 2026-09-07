use std::collections::HashSet;

use super::syntax::{is_test_only, parse_source};
pub(super) use super::token_calls::{macro_target_call_count, macro_target_reference_present};
use syn::visit::{self, Visit};
use syn::{ExprPath, File, Path, Type, UseTree};

const TARGET_TYPE: &str = "MacOsPendingCredentialServicePackageObservationV1";
const TARGET_CRATE: &str = "runne_macos_process_identity";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum TargetMethod {
    Capture,
    Verify,
}

macro_rules! visit_non_test_items {
    ($($method:ident: $item:ty => $delegate:ident),* $(,)?) => {
        $(fn $method(&mut self, node: &'ast $item) {
            if !is_test_only(&node.attrs) { visit::$delegate(self, node); }
        })*
    };
}

pub fn count_credential_service_calls(source: &str) -> usize {
    let file = parse_source(source);
    let names = discover_names(std::slice::from_ref(&file));
    count_file_calls(&file, &names)
}

pub fn count_workspace_credential_service_calls(sources: &[String]) -> usize {
    let files = sources
        .iter()
        .map(|source| parse_source(source))
        .collect::<Vec<_>>();
    let names = discover_names(&files);
    files
        .iter()
        .map(|file| count_file_calls(file, &names))
        .sum()
}

fn discover_names(files: &[File]) -> HashSet<String> {
    let mut names = HashSet::from([TARGET_TYPE.to_owned()]);
    loop {
        let mut discovered = HashSet::new();
        for file in files {
            BindingCollector {
                known: &names,
                discovered: &mut discovered,
            }
            .visit_file(file);
        }
        let before = names.len();
        names.extend(discovered);
        if names.len() == before {
            return names;
        }
    }
}

fn count_file_calls(file: &File, names: &HashSet<String>) -> usize {
    let mut references = ReferenceDetector {
        known: names,
        found: false,
    };
    references.visit_file(file);
    if !references.found {
        return 0;
    }
    super::receivers::count_calls(file, names)
}

struct BindingCollector<'a> {
    known: &'a HashSet<String>,
    discovered: &'a mut HashSet<String>,
}

impl<'ast> Visit<'ast> for BindingCollector<'_> {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if !is_test_only(&node.attrs) {
            collect_use_tree(&node.tree, &[], self.known, self.discovered);
        }
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if !is_test_only(&node.attrs) && type_targets(&node.ty, self.known) {
            self.discovered.insert(node.ident.to_string());
        }
    }

    fn visit_path(&mut self, node: &'ast Path) {
        if path_targets(node, self.known) {
            self.discovered.extend(
                node.segments
                    .iter()
                    .filter(|segment| segment.ident != TARGET_CRATE)
                    .map(|segment| segment.ident.to_string()),
            );
        }
    }

    visit_non_test_items! {
        visit_impl_item_const: syn::ImplItemConst => visit_impl_item_const,
        visit_impl_item_fn: syn::ImplItemFn => visit_impl_item_fn,
        visit_impl_item_macro: syn::ImplItemMacro => visit_impl_item_macro,
        visit_impl_item_type: syn::ImplItemType => visit_impl_item_type,
        visit_item_const: syn::ItemConst => visit_item_const,
        visit_item_enum: syn::ItemEnum => visit_item_enum,
        visit_item_fn: syn::ItemFn => visit_item_fn,
        visit_item_impl: syn::ItemImpl => visit_item_impl,
        visit_item_mod: syn::ItemMod => visit_item_mod,
        visit_item_static: syn::ItemStatic => visit_item_static,
        visit_item_struct: syn::ItemStruct => visit_item_struct,
        visit_item_trait: syn::ItemTrait => visit_item_trait,
        visit_item_union: syn::ItemUnion => visit_item_union,
        visit_trait_item_const: syn::TraitItemConst => visit_trait_item_const,
        visit_trait_item_fn: syn::TraitItemFn => visit_trait_item_fn,
        visit_trait_item_macro: syn::TraitItemMacro => visit_trait_item_macro,
        visit_trait_item_type: syn::TraitItemType => visit_trait_item_type,
    }
}

struct ReferenceDetector<'a> {
    known: &'a HashSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for ReferenceDetector<'_> {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if !is_test_only(&node.attrs) {
            self.found |= use_tree_targets(&node.tree, &[], self.known);
        }
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        self.found |= expr_path_target_method(node, self.known).is_some()
            || path_targets(&node.path, self.known);
        visit::visit_expr_path(self, node);
    }

    fn visit_path(&mut self, node: &'ast Path) {
        self.found |= path_targets(node, self.known);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.found |= macro_target_reference_present(node.tokens.clone(), self.known);
        visit::visit_macro(self, node);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if !is_test_only(&node.attrs) {
            self.found |= macro_target_reference_present(node.mac.tokens.clone(), self.known);
        }
    }

    visit_non_test_items! {
        visit_impl_item_const: syn::ImplItemConst => visit_impl_item_const,
        visit_impl_item_fn: syn::ImplItemFn => visit_impl_item_fn,
        visit_impl_item_macro: syn::ImplItemMacro => visit_impl_item_macro,
        visit_impl_item_type: syn::ImplItemType => visit_impl_item_type,
        visit_item_const: syn::ItemConst => visit_item_const,
        visit_item_enum: syn::ItemEnum => visit_item_enum,
        visit_item_fn: syn::ItemFn => visit_item_fn,
        visit_item_impl: syn::ItemImpl => visit_item_impl,
        visit_item_mod: syn::ItemMod => visit_item_mod,
        visit_item_static: syn::ItemStatic => visit_item_static,
        visit_item_struct: syn::ItemStruct => visit_item_struct,
        visit_item_trait: syn::ItemTrait => visit_item_trait,
        visit_item_union: syn::ItemUnion => visit_item_union,
        visit_trait_item_const: syn::TraitItemConst => visit_trait_item_const,
        visit_trait_item_fn: syn::TraitItemFn => visit_trait_item_fn,
        visit_trait_item_macro: syn::TraitItemMacro => visit_trait_item_macro,
        visit_trait_item_type: syn::TraitItemType => visit_trait_item_type,
    }
}

pub(super) fn path_targets(path: &Path, known: &HashSet<String>) -> bool {
    path.segments
        .iter()
        .any(|segment| known.contains(&segment.ident.to_string()))
}

pub(super) fn target_path_method(path: &Path, known: &HashSet<String>) -> Option<TargetMethod> {
    let segments = &path.segments;
    if segments.len() < 2 || !known.contains(&segments[segments.len() - 2].ident.to_string()) {
        return None;
    }
    method_name(segments.last()?.ident.to_string().as_str())
}

pub(super) fn expr_path_target_method(
    expr: &ExprPath,
    known: &HashSet<String>,
) -> Option<TargetMethod> {
    if let Some(qself) = &expr.qself {
        if !type_targets(&qself.ty, known) {
            return None;
        }
        return method_name(expr.path.segments.last()?.ident.to_string().as_str());
    }
    target_path_method(&expr.path, known)
}

fn method_name(name: &str) -> Option<TargetMethod> {
    match name {
        "capture_current" => Some(TargetMethod::Capture),
        "verify_exact" => Some(TargetMethod::Verify),
        _ => None,
    }
}

pub(super) fn type_targets(ty: &Type, known: &HashSet<String>) -> bool {
    match ty {
        Type::Path(path) => path_targets(&path.path, known),
        Type::Reference(reference) => type_targets(&reference.elem, known),
        Type::Paren(paren) => type_targets(&paren.elem, known),
        Type::Ptr(pointer) => type_targets(&pointer.elem, known),
        Type::Array(array) => type_targets(&array.elem, known),
        Type::Slice(slice) => type_targets(&slice.elem, known),
        Type::Tuple(tuple) => tuple.elems.iter().any(|item| type_targets(item, known)),
        _ => false,
    }
}

fn collect_use_tree(
    tree: &UseTree,
    prefix: &[String],
    known: &HashSet<String>,
    discovered: &mut HashSet<String>,
) {
    match tree {
        UseTree::Group(group) => group
            .items
            .iter()
            .for_each(|item| collect_use_tree(item, prefix, known, discovered)),
        UseTree::Name(name) => {
            if target_name(prefix, &name.ident.to_string(), known) {
                discovered.insert(name.ident.to_string());
            }
        }
        UseTree::Path(path) => {
            let mut next = prefix.to_vec();
            next.push(path.ident.to_string());
            collect_use_tree(&path.tree, &next, known, discovered);
        }
        UseTree::Rename(rename) => {
            if target_name(prefix, &rename.ident.to_string(), known) {
                discovered.insert(rename.rename.to_string());
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn target_name(prefix: &[String], leaf: &str, known: &HashSet<String>) -> bool {
    known.contains(leaf)
        || (prefix
            .iter()
            .any(|part| matches!(part.as_str(), TARGET_CRATE | "crate" | "self" | "super"))
            && leaf == TARGET_TYPE)
}

fn use_tree_targets(tree: &UseTree, prefix: &[String], known: &HashSet<String>) -> bool {
    match tree {
        UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_targets(item, prefix, known)),
        UseTree::Name(name) => target_name(prefix, &name.ident.to_string(), known),
        UseTree::Path(path) => {
            let mut next = prefix.to_vec();
            next.push(path.ident.to_string());
            use_tree_targets(&path.tree, &next, known)
        }
        UseTree::Rename(rename) => target_name(prefix, &rename.ident.to_string(), known),
        UseTree::Glob(_) => false,
    }
}
