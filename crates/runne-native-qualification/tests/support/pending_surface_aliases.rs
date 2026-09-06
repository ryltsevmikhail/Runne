use syn::ext::IdentExt;
use syn::{Item, Type, UseTree};

#[derive(Clone)]
pub struct Alias {
    pub left: String,
    pub right: String,
    pub kind: &'static str,
    pub raw: bool,
}

pub fn collect_aliases(items: &[Item], aliases: &mut Vec<Alias>) {
    for item in items {
        match item {
            Item::Type(item) => {
                if let Some(target) = type_name(&item.ty) {
                    aliases.push(Alias {
                        left: ident_name(&item.ident),
                        right: target.0,
                        kind: "type",
                        raw: ident_is_raw(&item.ident) || target.1,
                    });
                }
            }
            Item::Use(item) => collect_use_aliases(&item.tree, aliases),
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    collect_aliases(nested, aliases);
                }
            }
            _ => {}
        }
    }
}

fn collect_use_aliases(tree: &UseTree, aliases: &mut Vec<Alias>) {
    match tree {
        UseTree::Path(path) => collect_use_aliases(&path.tree, aliases),
        UseTree::Rename(rename) => aliases.push(Alias {
            left: ident_name(&rename.rename),
            right: ident_name(&rename.ident),
            kind: "use",
            raw: ident_is_raw(&rename.ident) || ident_is_raw(&rename.rename),
        }),
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_aliases(item, aliases);
            }
        }
        UseTree::Glob(_) | UseTree::Name(_) => {}
    }
}

pub fn type_name(ty: &Type) -> Option<(String, bool)> {
    match ty {
        Type::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .last()
            .map(|segment| (ident_name(&segment.ident), ident_is_raw(&segment.ident))),
        Type::Group(group) => type_name(&group.elem),
        Type::Paren(paren) => type_name(&paren.elem),
        Type::Reference(reference) => type_name(&reference.elem),
        _ => None,
    }
}

pub fn ident_name(ident: &syn::Ident) -> String {
    ident.unraw().to_string()
}

pub fn ident_is_raw(ident: &syn::Ident) -> bool {
    ident.to_string().starts_with("r#")
}
