use syn::punctuated::Punctuated;
use syn::visit::Visit;
use syn::{Attribute, Meta, Path, Token, Type, UseTree, Visibility};

pub struct UseLeaf {
    pub segments: Vec<String>,
    pub local: Option<String>,
    pub glob: bool,
}

pub fn use_leaves(tree: &UseTree) -> Vec<UseLeaf> {
    fn collect(tree: &UseTree, prefix: &mut Vec<String>, output: &mut Vec<UseLeaf>) {
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                collect(&path.tree, prefix, output);
                prefix.pop();
            }
            UseTree::Name(name) => {
                let mut segments = prefix.clone();
                segments.push(name.ident.to_string());
                output.push(UseLeaf {
                    local: Some(name.ident.to_string()),
                    segments,
                    glob: false,
                });
            }
            UseTree::Rename(rename) => {
                let mut segments = prefix.clone();
                segments.push(rename.ident.to_string());
                output.push(UseLeaf {
                    local: Some(rename.rename.to_string()),
                    segments,
                    glob: false,
                });
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    collect(item, prefix, output);
                }
            }
            UseTree::Glob(_) => output.push(UseLeaf {
                segments: prefix.clone(),
                local: None,
                glob: true,
            }),
        }
    }

    let mut output = Vec::new();
    collect(tree, &mut Vec::new(), &mut output);
    output
}

pub fn path_mentions(path: &Path, names: &std::collections::HashSet<String>) -> bool {
    let mut visitor = FamilyVisitor {
        names,
        found: false,
    };
    visitor.visit_path(path);
    visitor.found
}

pub fn type_mentions(ty: &Type, names: &std::collections::HashSet<String>) -> bool {
    let mut visitor = FamilyVisitor {
        names,
        found: false,
    };
    visitor.visit_type(ty);
    visitor.found
}

pub fn alias_mentions(alias: &syn::ItemType, names: &std::collections::HashSet<String>) -> bool {
    let mut visitor = FamilyVisitor {
        names,
        found: false,
    };
    visitor.visit_item_type(alias);
    visitor.found
}

pub fn impl_type_mentions(
    item: &syn::ImplItemType,
    names: &std::collections::HashSet<String>,
) -> bool {
    let mut visitor = FamilyVisitor {
        names,
        found: false,
    };
    visitor.visit_impl_item_type(item);
    visitor.found
}

pub fn trait_type_mentions(
    item: &syn::TraitItemType,
    names: &std::collections::HashSet<String>,
) -> bool {
    let mut visitor = FamilyVisitor {
        names,
        found: false,
    };
    visitor.visit_trait_item_type(item);
    visitor.found
}

pub fn signature_mentions(
    signature: &syn::Signature,
    names: &std::collections::HashSet<String>,
) -> bool {
    let mut visitor = FamilyVisitor {
        names,
        found: false,
    };
    visitor.visit_signature(signature);
    visitor.found
}

struct FamilyVisitor<'a> {
    names: &'a std::collections::HashSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for FamilyVisitor<'_> {
    fn visit_path(&mut self, path: &'ast Path) {
        self.found |= path
            .segments
            .iter()
            .any(|part| self.names.contains(&part.ident.to_string()));
        syn::visit::visit_path(self, path);
    }

    fn visit_type(&mut self, ty: &'ast Type) {
        // No expansion/type resolution: unknown types may belong to either guarded
        // family. This rejects their aliases and routes signatures to the exact
        // ingress allowlist, including when the macro tokens name neither family.
        // A qualified associated projection can resolve through an external
        // trait/default without naming either family. Treat it as unresolved.
        if matches!(ty, Type::Macro(_) | Type::Verbatim(_))
            || matches!(ty, Type::Path(path) if path.qself.is_some())
        {
            self.found = true;
        } else {
            syn::visit::visit_type(self, ty);
        }
    }
}

pub fn derive_names(attributes: &[Attribute]) -> Vec<String> {
    let mut output = Vec::new();
    for attribute in attributes
        .iter()
        .filter(|attr| attr.path().is_ident("derive"))
    {
        if let Ok(paths) =
            attribute.parse_args_with(Punctuated::<Path, Token![,]>::parse_terminated)
        {
            output.extend(
                paths
                    .iter()
                    .filter_map(|path| path.segments.last())
                    .map(|segment| segment.ident.to_string()),
            );
        }
    }
    output.sort();
    output
}

pub fn is_doc_hidden(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("doc")
            && attribute
                .parse_args::<syn::Ident>()
                .is_ok_and(|ident| ident == "hidden")
    })
}

pub fn has_cfg_attr(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg_attr"))
}

pub fn is_test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if !attribute.path().is_ident("cfg") {
            return false;
        }
        attribute
            .parse_args::<Meta>()
            .is_ok_and(|meta| meta_is_test_only(&meta))
    })
}

pub fn meta_is_test_only(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) if list.path.is_ident("all") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .is_ok_and(|items| items.iter().any(meta_is_test_only)),
        Meta::List(list) if list.path.is_ident("any") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .is_ok_and(|items| !items.is_empty() && items.iter().all(meta_is_test_only)),
        Meta::List(_) => false,
        Meta::NameValue(_) => false,
    }
}

pub fn is_public(visibility: &Visibility) -> bool {
    !matches!(visibility, Visibility::Inherited)
}

pub fn item_is_test_only(item: &syn::Item) -> bool {
    let attrs = match item {
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
        _ => return false,
    };
    is_test_only(attrs)
}

pub fn impl_item_is_test_only(item: &syn::ImplItem) -> bool {
    let attrs = match item {
        syn::ImplItem::Const(item) => &item.attrs,
        syn::ImplItem::Fn(item) => &item.attrs,
        syn::ImplItem::Macro(item) => &item.attrs,
        syn::ImplItem::Type(item) => &item.attrs,
        _ => return false,
    };
    is_test_only(attrs)
}

pub fn trait_item_is_test_only(item: &syn::TraitItem) -> bool {
    let attrs = match item {
        syn::TraitItem::Const(item) => &item.attrs,
        syn::TraitItem::Fn(item) => &item.attrs,
        syn::TraitItem::Macro(item) => &item.attrs,
        syn::TraitItem::Type(item) => &item.attrs,
        _ => return false,
    };
    is_test_only(attrs)
}
