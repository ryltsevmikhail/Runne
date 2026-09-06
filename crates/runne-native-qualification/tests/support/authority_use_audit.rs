use syn::{UseTree, Visibility};

const SENSITIVE: &[&str] = &[
    "VerifiedQualificationRunContext",
    "PendingQualificationAdmission",
    "QualificationRunContextVerifier",
    "PendingQualificationFault",
    "VerifiedQualificationFault",
];

pub fn violation(item: &syn::ItemUse, source: &str, depth: usize) -> Option<String> {
    let mut entries = Vec::new();
    flatten_use(&item.tree, "", &mut entries);
    let carries_authority = entries.iter().any(|entry| {
        SENSITIVE.iter().any(|name| {
            entry
                .split(" as ")
                .next()
                .is_some_and(|path| path.ends_with(name))
        })
    });
    let renamed_authority = carries_authority && entries.iter().any(|entry| entry.contains(" as "));
    let guarded_glob = entries.iter().any(|entry| {
        entry.ends_with("::*")
            && [
                "admission",
                "context_model",
                "context_verification",
                "model",
                "pending",
            ]
            .iter()
            .any(|module| entry.trim_end_matches("::*").ends_with(module))
    });
    let public_noncanonical = matches!(item.vis, Visibility::Public(_))
        && carries_authority
        && !(depth == 0 && exact_root_reexport(source, item));
    (renamed_authority || guarded_glob || public_noncanonical)
        .then(|| format!("{source}: forbidden authority use/re-export {entries:?}"))
}

fn flatten_use(tree: &UseTree, prefix: &str, entries: &mut Vec<String>) {
    match tree {
        UseTree::Path(path) => {
            let next = joined(prefix, &path.ident.to_string());
            flatten_use(&path.tree, &next, entries);
        }
        UseTree::Name(name) => entries.push(joined(prefix, &name.ident.to_string())),
        UseTree::Rename(rename) => entries.push(format!(
            "{} as {}",
            joined(prefix, &rename.ident.to_string()),
            rename.rename
        )),
        UseTree::Glob(_) => entries.push(joined(prefix, "*")),
        UseTree::Group(group) => {
            for nested in &group.items {
                flatten_use(nested, prefix, entries);
            }
        }
    }
}

fn joined(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}::{name}")
    }
}

fn exact_root_reexport(source: &str, item: &syn::ItemUse) -> bool {
    if source != "lib.rs" || !item.attrs.is_empty() {
        return false;
    }
    let allowed = [
        "pub use admission::{PendingQualificationAdmission, QualificationAdmissionError};",
        "pub use context_model::{QualificationRunContextError, QualificationRunContextExpectation, QualificationScenario, VerifiedQualificationRunContext,};",
        "pub use context_verification::QualificationRunContextVerifier;",
        "pub use model::{QualificationFaultContext, QualificationFaultError, QualificationFaultSelector, QualificationProcessRole, VerifiedQualificationFault,};",
        "pub use pending::PendingQualificationFault;",
    ];
    allowed.into_iter().any(|source| {
        let expected =
            syn::parse_str::<syn::ItemUse>(source).expect("reviewed authority re-export");
        item.leading_colon == expected.leading_colon && item.tree == expected.tree
    })
}
