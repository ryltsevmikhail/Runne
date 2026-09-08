pub(super) struct UseAlias {
    pub(super) name: String,
    pub(super) target: Vec<String>,
}

pub(super) fn use_aliases(tree: &syn::UseTree) -> Vec<UseAlias> {
    let mut aliases = Vec::new();
    collect(tree, &mut Vec::new(), &mut aliases);
    aliases
}

fn collect(tree: &syn::UseTree, prefix: &mut Vec<String>, aliases: &mut Vec<UseAlias>) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect(&path.tree, prefix, aliases);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut target = prefix.clone();
            target.push(name.ident.to_string());
            aliases.push(UseAlias {
                name: name.ident.to_string(),
                target,
            });
        }
        syn::UseTree::Rename(rename) => {
            let mut target = prefix.clone();
            target.push(rename.ident.to_string());
            aliases.push(UseAlias {
                name: rename.rename.to_string(),
                target,
            });
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect(item, prefix, aliases);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}
